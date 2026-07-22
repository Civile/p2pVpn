//! # Control plane: backoffice web + segnalazione + rendez-vous UDP
//!
//! Questo binario va compilato ed eseguito sulla tua VPS (DigitalOcean),
//! perché deve avere un IP **pubblico** raggiungibile dai client.
//!
//! Espone tre servizi sullo stesso runtime tokio:
//! 1. **HTTP** (default `:8080`) — il backoffice web (`p2p_holepunch::web`):
//!    registrazione/login, elenco dispositivi, device-code flow per il client.
//! 2. **TCP** (default `:47100`) — segnalazione. Il client si autentica con la
//!    `auth_key` ottenuta al login; il server lo risolve nel suo account.
//! 3. **UDP** (default `:47101`) — impara l'endpoint UDP pubblico di ogni
//!    dispositivo (IP:porta post-NAT) per il successivo hole punching.
//!
//! Il collegamento tra due dispositivi (invio di `PeerInfo`) è avviato
//! dall'utente dal backoffice ("Collega"). Il server non fa da relay: scambia
//! gli indirizzi e si fa da parte.
//!
//! Variabili d'ambiente:
//! - `DB_PATH`     (default `data.db`)
//! - `HTTP_PORT`   (default `8080`)
//! - `PUBLIC_URL`  (default `http://127.0.0.1:<HTTP_PORT>`) — base dei link
//!   mostrati al client nel device-code flow. In produzione: l'URL pubblico.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex};

use p2p_holepunch::db;
use p2p_holepunch::proto::relay;
use p2p_holepunch::web::{self, AppState, Live, LiveDevice};
use p2p_holepunch::{ClientMessage, ServerMessage, UdpMessage};

// Porte di segnalazione (devono combaciare con quelle del client).
const TCP_PORT: u16 = 47100;
const UDP_PORT: u16 = 47101;

/// Tabella del relay condivisa (id ↔ endpoint), dietro un `std::sync::Mutex`
/// (lock brevissimo, niente await) per non contendere il `Mutex` async dello
/// stato `live` sul percorso caldo dei dati VPN. La logica vive in
/// `proto::relay::Table` (così è testabile e riusata).
type Relay = Arc<std::sync::Mutex<relay::Table>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db_path = std::env::var("DB_PATH").unwrap_or_else(|_| "data.db".to_string());
    let http_port: u16 = std::env::var("HTTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let public_url = std::env::var("PUBLIC_URL")
        .unwrap_or_else(|_| format!("http://127.0.0.1:{http_port}"));

    // Storage SQLite condiviso.
    let conn = db::open(&db_path)?;
    let db = Arc::new(Mutex::new(conn));
    println!("[Server] Database SQLite: {db_path}");

    // Stato live: dispositivi collegati in questo momento.
    let live: Live = Arc::new(Mutex::new(std::collections::HashMap::new()));
    // Tabella del relay VPN (id ↔ endpoint), condivisa tra UDP e TCP.
    let relay: Relay = Arc::new(std::sync::Mutex::new(relay::Table::default()));

    // --- HTTP: backoffice web ---
    let state = AppState {
        db: db.clone(),
        live: live.clone(),
        public_url: public_url.clone(),
    };
    let http = TcpListener::bind(("0.0.0.0", http_port)).await?;
    println!("[Server] Backoffice web in ascolto su http://0.0.0.0:{http_port}  (pubblico: {public_url})");
    let app = web::router(state);
    tokio::spawn(async move {
        if let Err(e) = axum::serve(http, app.into_make_service()).await {
            eprintln!("[HTTP] errore: {e}");
        }
    });

    // --- UDP: apprendimento endpoint pubblici + relay VPN ---
    let udp = Arc::new(UdpSocket::bind(("0.0.0.0", UDP_PORT)).await?);
    println!("[Server] UDP in ascolto su 0.0.0.0:{UDP_PORT} (endpoint + relay VPN)");
    tokio::spawn(run_udp(udp.clone(), live.clone(), relay.clone()));

    // --- TCP: segnalazione ---
    let tcp = TcpListener::bind(("0.0.0.0", TCP_PORT)).await?;
    println!("[Server] TCP di segnalazione in ascolto su 0.0.0.0:{TCP_PORT}");
    loop {
        let (stream, peer) = tcp.accept().await?;
        tokio::spawn(handle_tcp(stream, peer, db.clone(), live.clone(), relay.clone()));
    }
}

/// Gestisce una singola connessione TCP di segnalazione (un dispositivo).
async fn handle_tcp(
    stream: TcpStream,
    peer: SocketAddr,
    db: Arc<Mutex<rusqlite::Connection>>,
    live: Live,
    relay: Relay,
) {
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();

    // Canale interno: il task UDP e il backoffice ("Collega") spingono messaggi
    // verso questo dispositivo scrivendo su `tx`.
    let (tx, mut rx) = mpsc::unbounded_channel::<ServerMessage>();

    // Task di scrittura: serializza i messaggi in uscita come JSON + newline.
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let mut data = serde_json::to_vec(&msg).unwrap_or_default();
            data.push(b'\n');
            if write_half.write_all(&data).await.is_err() {
                break; // connessione chiusa
            }
        }
    });

    // Identità (device_id, user_id) risolta dopo un Register andato a buon fine.
    let mut identity: Option<(String, i64)> = None;

    while let Ok(Some(line)) = lines.next_line().await {
        if line.trim().is_empty() {
            continue;
        }
        let msg: ClientMessage = match serde_json::from_str(&line) {
            Ok(m) => m,
            Err(e) => {
                let _ = tx.send(ServerMessage::Error {
                    message: format!("JSON non valido: {e}"),
                });
                continue;
            }
        };

        match msg {
            ClientMessage::Register { auth_key, wg_public } => {
                // Autentica la chiave: risolve dispositivo + account.
                let device = {
                    let conn = db.lock().await;
                    db::device_by_auth_key(&conn, &auth_key).ok().flatten()
                };
                let Some(device) = device else {
                    let _ = tx.send(ServerMessage::Error {
                        message: "auth_key non valida: esegui di nuovo il login del client.".into(),
                    });
                    break;
                };

                {
                    let conn = db.lock().await;
                    let _ = db::touch_device(&conn, &device.id);
                    // Aggiorna la chiave pubblica WireGuard, se il client l'ha inviata.
                    if let Some(pk) = &wg_public {
                        let _ = db::set_wg_public(&conn, &device.id, pk);
                    }
                }
                let wg_public = wg_public.or(device.wg_public.clone());
                {
                    let mut guard = live.lock().await;
                    guard.insert(
                        device.id.clone(),
                        LiveDevice {
                            user_id: device.user_id,
                            name: device.name.clone(),
                            tx: tx.clone(),
                            udp_addr: None,
                            is_exit_node: device.is_exit_node,
                            using_exit: None,
                            vip: device.vip.clone(),
                            wg_public,
                        },
                    );
                }
                identity = Some((device.id.clone(), device.user_id));
                let _ = tx.send(ServerMessage::Registered {
                    device_id: device.id.clone(),
                    vip: device.vip.clone(),
                    info: "Registrazione TCP ok. Invia ora datagrammi UDP per \
                           pubblicare il tuo endpoint."
                        .to_string(),
                });
                let _ = tx.send(ServerMessage::Waiting);
                println!(
                    "[TCP] Online '{}' (device_id={} user={} da {peer})",
                    device.name, device.id, device.user_id
                );
            }

            ClientMessage::UseExitNode { exit_device_id } => {
                let Some((my_id, user_id)) = identity.clone() else {
                    let _ = tx.send(ServerMessage::Error {
                        message: "Registrati prima di scegliere un exit node.".into(),
                    });
                    continue;
                };

                // Valida il target: deve essere un dispositivo dello stesso
                // account, online e marcato come exit node (oppure `None` per
                // annullare la scelta).
                let (ok, message) = {
                    let mut guard = live.lock().await;
                    match &exit_device_id {
                        None => {
                            if let Some(d) = guard.get_mut(&my_id) {
                                d.using_exit = None;
                            }
                            (true, "Exit node disattivato: traffico diretto.".to_string())
                        }
                        Some(target) if target == &my_id => {
                            (false, "Non puoi usare te stesso come exit node.".to_string())
                        }
                        Some(target) => match guard.get(target) {
                            Some(t) if t.user_id == user_id && t.is_exit_node => {
                                let name = t.name.clone();
                                if let Some(d) = guard.get_mut(&my_id) {
                                    d.using_exit = Some(target.clone());
                                }
                                (true, format!("Exit node impostato: '{name}'."))
                            }
                            Some(_) => (false, "Quel dispositivo non è un exit node valido.".to_string()),
                            None => (false, "Exit node non online.".to_string()),
                        },
                    }
                };

                if ok {
                    println!("[Exit] '{my_id}' usa exit_node={exit_device_id:?}");
                }
                let _ = tx.send(ServerMessage::ExitNodeSet {
                    exit_device_id,
                    ok,
                    message,
                });
            }
        }
    }

    // Connessione caduta: rimuovi dallo stato live + relay e avvisa la mesh.
    if let Some((id, user_id)) = identity {
        live.lock().await.remove(&id);
        relay.lock().unwrap().remove(&id);
        web::peer_gone(&live, user_id, &id).await;
        println!("[TCP] Offline device_id={id}");
    }
}

/// Riceve i datagrammi UDP: apprende gli endpoint pubblici (JSON `UdpRegister`)
/// e **instrada i frame di relay VPN** (byte magico `0x72`) tra i dispositivi.
async fn run_udp(socket: Arc<UdpSocket>, live: Live, relay: Relay) {
    // Buffer ampio: i frame di relay portano un pacchetto WireGuard (fino a ~1.4 KB).
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[UDP] errore in recv_from: {e}");
                continue;
            }
        };

        // --- Percorso caldo: frame di relay VPN ---
        // Non è JSON: è un datagramma WireGuard cifrato da inoltrare. Riscriviamo
        // l'id di destinazione con quello del mittente (così il destinatario sa
        // da chi arriva) e lo spediamo al suo endpoint pubblico.
        if relay::is_relay(&buf[..n]) {
            let out = relay.lock().unwrap().route(src, &buf[..n]);
            if let Some((bytes, dst_addr)) = out {
                let _ = socket.send_to(&bytes, dst_addr).await;
            }
            continue;
        }

        let text = String::from_utf8_lossy(&buf[..n]);
        let msg: UdpMessage = match serde_json::from_str(text.trim()) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[UDP] JSON non valido da {src}: {e}");
                continue;
            }
        };

        match msg {
            UdpMessage::UdpRegister { device_id } => {
                // Aggiorna la tabella del relay: id ↔ endpoint pubblico corrente.
                relay.lock().unwrap().upsert(&device_id, src);
                // Se l'endpoint è nuovo/cambiato, memorizziamo l'utente per
                // (ri)formare la mesh dopo aver rilasciato il lock.
                let (known, changed_user) = {
                    let mut guard = live.lock().await;
                    match guard.get_mut(&device_id) {
                        Some(d) => {
                            // `src` è l'endpoint pubblico così come lo vede il
                            // server: esattamente ciò che serve al peer.
                            let changed = d.udp_addr != Some(src);
                            d.udp_addr = Some(src);
                            if changed {
                                println!("[UDP] Endpoint pubblico di '{}' = {src}", d.name);
                                (true, Some(d.user_id))
                            } else {
                                (true, None)
                            }
                        }
                        None => (false, None),
                    }
                };
                if known {
                    // Piccolo ack UDP: conferma la ricezione al client.
                    let _ = socket.send_to(b"{\"type\":\"UdpAck\"}", src).await;
                } else {
                    eprintln!("[UDP] device_id non online (registrarsi prima via TCP): '{device_id}'");
                }
                // Nuovo endpoint noto → collega questo dispositivo a tutta la mesh.
                if let Some(user_id) = changed_user {
                    web::mesh_announce(&live, user_id, &device_id).await;
                }
            }
        }
    }
}
