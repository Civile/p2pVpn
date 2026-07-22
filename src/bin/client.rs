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
#[cfg(feature = "vpn")]
use p2p_holepunch::{proto::relay, vpn::Endpoint};

// ============================================================================
//  CONFIGURAZIONE — >>> INSERISCI QUI L'IP DEL TUO SERVER <<<
// ============================================================================
// In test locale lascia "127.0.0.1". In produzione: l'IP pubblico del droplet.
// Tutto sovrascrivibile a runtime via variabili d'ambiente:
//   P2P_SERVER, P2P_HTTP_PORT, P2P_TCP_PORT, P2P_UDP_PORT.
const SERVER_IP: &str = "abc.edoardocasella.it";
const HTTP_PORT: u16 = 443; // backoffice web (device-code flow, HTTPS)
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

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return Ok(());
    }

    if args.iter().any(|a| a == "--reset") {
        let path = config_path();
        let _ = std::fs::remove_file(&path);
        println!("[Client] Config rimossa: {}", path.display());
        return Ok(());
    }

    // Parsing argomenti:
    //   [nome]                 nome del dispositivo (al primo login)
    //   --use-exit <nome>      instrada TUTTO il traffico attraverso l'exit <nome>
    //   --exit-node            fai da exit node per gli altri dispositivi
    //   --no-route             col tunnel client, NON dirottare il default (solo TUN)
    //   --list-exits           elenca gli exit node disponibili ed esci
    //   --install-service      "connetti all'avvio": installa+abilita il servizio systemd
    //   --uninstall-service    rimuovi il servizio di avvio automatico
    let be_exit = args.iter().any(|a| a == "--exit-node");
    let list_exits = args.iter().any(|a| a == "--list-exits");
    let full_tunnel = !args.iter().any(|a| a == "--no-route");
    let mut desired_exit: Option<String> = None;
    let mut device_name: Option<String> = None;
    // Endpoint diretto dell'exit (IP:porta): bypassa l'hole punching e manda i
    // pacchetti WireGuard direttamente lì (per Pi con porta UDP fissa + port
    // forwarding sul router, o per test su LAN puntando all'IP locale del Pi).
    // Da flag `--exit-endpoint` o da env `P2P_EXIT_ENDPOINT`.
    let mut exit_endpoint: Option<String> =
        std::env::var("P2P_EXIT_ENDPOINT").ok().filter(|s| !s.is_empty());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--use-exit" => desired_exit = it.next().cloned(),
            "--exit-endpoint" => exit_endpoint = it.next().cloned(),
            s if s.starts_with("--") => {}
            s if device_name.is_none() => device_name = Some(s.to_string()),
            _ => {}
        }
    }

    // "Connetti all'avvio": gestione del servizio systemd (non entra nel loop).
    if args.iter().any(|a| a == "--install-service") {
        return install_service(be_exit);
    }
    if args.iter().any(|a| a == "--uninstall-service") {
        return uninstall_service();
    }

    if be_exit {
        println!("[Client] Modalità EXIT NODE attiva (il data plane richiede la feature `vpn` e privilegi root).");
    }
    if let Some(ref e) = desired_exit {
        let mode = if full_tunnel { "full tunnel (VPN reale)" } else { "solo TUN, routing manuale" };
        println!("[Client] Instraderò il traffico tramite l'exit node '{e}' quando sarà online — {mode}.");
    }

    // Ctrl-C o SIGTERM (es. `systemctl stop`, o la GUI che ferma il tunnel):
    // ripristina sempre il routing prima di uscire (evita di restare isolati).
    // Senza la feature `vpn`, `restore` è un no-op innocuo.
    #[cfg(feature = "vpn")]
    tokio::spawn(async {
        wait_for_shutdown_signal().await;
        println!("\n[Client] Interruzione: ripristino il routing di rete…");
        p2p_holepunch::route::restore();
        std::process::exit(0);
    });

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

    // Endpoint diretto dell'exit, se richiesto (risolto host:porta → SocketAddr).
    let exit_addr_override: Option<SocketAddr> = match &exit_endpoint {
        Some(s) => match s.rsplit_once(':').and_then(|(h, p)| p.parse::<u16>().ok().map(|p| (h, p))) {
            Some((host, p)) => match resolve(host, p).await {
                Ok(a) => {
                    println!("[Exit] Endpoint DIRETTO dell'exit: {a} (bypasso l'hole punching).");
                    Some(a)
                }
                Err(e) => {
                    eprintln!("[Exit] endpoint '{s}' non risolvibile ({e}); uso l'hole punching.");
                    None
                }
            },
            None => {
                eprintln!("[Exit] formato --exit-endpoint non valido: '{s}' (atteso IP:porta).");
                None
            }
        },
        None => None,
    };
    // Senza la feature `vpn` l'endpoint diretto non viene usato (nessun tunnel).
    #[cfg(not(feature = "vpn"))]
    let _ = exit_addr_override;

    // 3) Un unico socket UDP, riusato per server e per peer (mapping NAT coerente).
    //    Con P2P_BIND_PORT si fissa la porta (per l'exit dietro port forwarding).
    let bind_port = port("P2P_BIND_PORT", 0);
    let udp = Arc::new(UdpSocket::bind(("0.0.0.0", bind_port)).await?);
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
    //     L'exit usa sempre 10.7.0.1 (EXIT_VIP) come indirizzo del proprio TUN:
    //     non dipende dal vip IPAM, così parte anche se la config è "vecchia".
    #[cfg(feature = "vpn")]
    if be_exit {
        match cfg.wg_private.clone() {
            Some(sk) => {
                p2p_holepunch::vpn::spawn_exit_node(udp.clone(), sk, p2p_holepunch::vpn::EXIT_VIP)
            }
            None => eprintln!("[Client] Exit node: manca la chiave WireGuard (rifai il login del client)."),
        }
    }

    // 7) Mesh: per ogni PeerInfo apriamo (o aggiorniamo) l'hole punching verso
    //    quel peer. I PeerInfo arrivano in continuazione, man mano che altri
    //    dispositivi dell'account entrano; PeerGone quando escono.
    if list_exits {
        println!("[Client] Raccolgo gli exit node disponibili (attendo qualche secondo)…");
    } else {
        println!("[Client] In attesa dei peer dell'account (mesh)...");
    }
    let mut senders: HashMap<String, (SocketAddr, JoinHandle<()>)> = HashMap::new();
    // Stato della scelta exit node: (device_id, endpoint, chiave pubblica WG).
    let mut exit_requested = false;
    let mut exit_peer: Option<(String, SocketAddr, Option<String>)> = None;
    // Exit node visti (per `--list-exits`): (nome, device_id).
    let mut available_exits: Vec<(String, String)> = Vec::new();
    // In modalità elenco, esci dopo qualche secondo di raccolta.
    let list_deadline =
        list_exits.then(|| tokio::time::Instant::now() + Duration::from_secs(6));
    loop {
        let line = if let Some(dl) = list_deadline {
            tokio::select! {
                r = lines.next_line() => match r? {
                    Some(l) => l,
                    None => break,
                },
                _ = tokio::time::sleep_until(dl) => {
                    print_exits(&available_exits);
                    return Ok(());
                }
            }
        } else {
            match lines.next_line().await? {
                Some(l) => l,
                None => {
                    eprintln!("[Client] Il server ha chiuso la connessione TCP.");
                    break;
                }
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<ServerMessage>(&line)? {
            ServerMessage::Registered { info, vip, .. } => {
                // Il server assegna il vip (IPAM) e lo manda qui a ogni connessione.
                // Lo adottiamo se la config locale non ce l'ha (es. login fatto
                // dalla GUI, che non salvava il vip): serve al tunnel client.
                if cfg.vip.is_none() {
                    if let Some(v) = vip {
                        println!("[Client] IP virtuale assegnato dal server: {v}");
                        cfg.vip = Some(v);
                        let _ = save_config(&cfg);
                    }
                }
                println!("[Client] {info}");
            }
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
                // Tieni aggiornato l'elenco degli exit node disponibili.
                if is_exit_node && !available_exits.iter().any(|(_, id)| id == &peer_id) {
                    available_exits.push((peer_name.clone(), peer_id.clone()));
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
                            println!("[Exit] Richiesto '{peer_name}' come exit node (endpoint diretto {peer_addr}).");
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
                    if let Some((peer_id, _peer_addr, pk)) = &exit_peer {
                        // Il nostro IP virtuale: quello del server se disponibile,
                        // altrimenti derivato in modo deterministico dal device_id
                        // (così il tunnel parte anche senza vip nella config).
                        let vip = cfg
                            .vip
                            .as_deref()
                            .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
                            .unwrap_or_else(|| p2p_holepunch::vpn::client_vip(&cfg.device_id));
                        // Scelta del percorso:
                        //  • `--exit-endpoint IP:porta` → invio DIRETTO (LAN o port
                        //    forwarding, massima performance);
                        //  • altrimenti → RELAY sul server (default, funziona
                        //    ovunque anche dietro CGNAT, come Tailscale/DERP).
                        let exit_ep = match exit_addr_override {
                            Some(direct) => Endpoint::Direct(direct),
                            None => Endpoint::Relay { relay: server_udp, peer: peer_id.clone() },
                        };
                        match (pk.clone(), cfg.wg_private.clone()) {
                            (Some(pk), Some(sk)) => {
                                println!("[Exit] (vpn) avvio tunnel CIFRATO ({exit_ep}) come {vip} (richiede root/TUN)…");
                                p2p_holepunch::vpn::spawn_client_tunnel(udp.clone(), exit_ep, sk, pk, vip, full_tunnel);
                            }
                            (None, _) => eprintln!(
                                "[Exit] (vpn) manca la chiave WireGuard dell'exit: è compilato con --features vpn ed è online?"
                            ),
                            (_, None) => eprintln!(
                                "[Exit] (vpn) manca la nostra chiave WireGuard: rifai il login del client (con --features vpn)."
                            ),
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
    // Uscendo dal loop (server disconnesso) ripristina sempre il routing.
    #[cfg(feature = "vpn")]
    p2p_holepunch::route::restore();
    Ok(())
}

/// Attende un segnale di spegnimento: Ctrl-C (SIGINT) oppure SIGTERM (inviato da
/// `systemctl stop` o dalla GUI quando ferma il tunnel). Su Unix ascolta
/// entrambi; altrove solo Ctrl-C.
#[cfg(feature = "vpn")]
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Stampa gli exit node raccolti (`--list-exits`).
fn print_exits(exits: &[(String, String)]) {
    if exits.is_empty() {
        println!("\n[Exit] Nessun exit node disponibile al momento.");
        println!("[Exit] Assicurati che un dispositivo sia marcato come exit node nel backoffice e sia online.");
        return;
    }
    println!("\n[Exit] Exit node disponibili ({}):", exits.len());
    for (name, id) in exits {
        println!("  • {name}   (id: {id})");
    }
    println!("\nUsalo con:  client --use-exit \"<nome>\"   (con sudo e build --features vpn)");
}

/// Stampa l'aiuto della riga di comando.
fn print_help() {
    println!(
        "P2P VPN client — uso:\n\
         \n\
         client [\"nome device\"]        login (se serve) + mesh, in attesa dei peer\n\
         client --list-exits           elenca gli exit node disponibili ed esci\n\
         client --use-exit \"<nome>\"     instrada TUTTO il traffico via l'exit <nome> (VPN reale)\n\
         \x20                             di default passa dal RELAY sul server: funziona ovunque,\n\
         \x20                             anche dietro CGNAT, senza toccare il router.\n\
         client --use-exit \"<nome>\" --no-route   crea solo il TUN, routing manuale\n\
         client --use-exit \"<nome>\" --exit-endpoint IP:porta   forza il percorso DIRETTO\n\
         \x20                                      (LAN o Pi con porta fissa + port forwarding: più veloce)\n\
         client --exit-node            fai da exit node per gli altri dispositivi\n\
         client --install-service      \"connetti all'avvio\": servizio systemd (Linux/Raspberry)\n\
         client --install-service --exit-node   avvio automatico come exit node\n\
         client --uninstall-service    rimuovi l'avvio automatico\n\
         client --reset                cancella l'identità locale (rifà il login)\n\
         client --help                 questo aiuto\n\
         \n\
         Note:\n\
         - Il tunnel reale richiede la build con `--features vpn` e privilegi root (sudo).\n\
         - Variabili d'ambiente: P2P_SERVER, P2P_HTTP_PORT, P2P_TCP_PORT, P2P_UDP_PORT.\n\
         - P2P_BIND_PORT: fissa la porta UDP locale (per l'exit dietro port forwarding).\n\
         - P2P_EXIT_ENDPOINT: come --exit-endpoint, ma da variabile d'ambiente.\n"
    );
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
            // `n` (dimensione del datagramma) serve solo al demux VPN della feature.
            #[cfg(not(feature = "vpn"))]
            let _ = n;
            // Frame di relay dal server → traffico VPN inoltrato da un peer. Il
            // server ha riscritto l'id col mittente: lo usiamo come identità
            // dell'Endpoint (così la risposta ripercorre il relay).
            #[cfg(feature = "vpn")]
            if src == server_udp && relay::is_relay(&buf[..n]) {
                if let Some((peer_id, wg)) = relay::parse(&buf[..n]) {
                    p2p_holepunch::vpn::deliver_inbound(
                        Endpoint::Relay { relay: server_udp, peer: peer_id.to_string() },
                        wg.to_vec(),
                    );
                }
                continue;
            }
            if src == server_udp {
                continue; // ack/echo JSON del server: non è traffico peer
            }
            // Con la feature `vpn`, i datagrammi VPN diretti vanno al tunnel.
            #[cfg(feature = "vpn")]
            if p2p_holepunch::vpn::is_vpn(&buf[..n]) {
                if let Some(pkt) = p2p_holepunch::vpn::decap(&buf[..n]) {
                    p2p_holepunch::vpn::deliver_inbound(Endpoint::Direct(src), pkt.to_vec());
                }
                continue;
            }
            // Primo pacchetto da questo peer: buco NAT aperto. I PING successivi
            // sono solo keepalive: non li stampiamo (riempirebbero i log e
            // nasconderebbero le righe utili del tunnel).
            if established.insert(src.ip()) {
                println!("[Punch] ✅ Connessione P2P diretta stabilita con {src}!");
            }
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
    // Porta 443 => TLS (produzione dietro nginx/HTTPS); altrimenti in chiaro (dev locale).
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

// --------------------------------------------------- connetti all'avvio ---
//
// Gestione del servizio systemd (solo Linux, es. Raspberry Pi) per far partire
// il client automaticamente al boot — la "connessione all'avvio". Il servizio
// riusa l'identità già salvata (fai prima il login una volta, interattivo).

/// Nome del servizio systemd installato.
#[cfg(target_os = "linux")]
const SERVICE_NAME: &str = "p2p-vpn";

/// Home reale dell'utente, rispettando `sudo` (così troviamo `config.json`
/// anche quando installiamo il servizio con `sudo`).
#[cfg(target_os = "linux")]
fn real_home() -> String {
    if let Ok(user) = std::env::var("SUDO_USER") {
        if !user.is_empty() && user != "root" {
            return format!("/home/{user}");
        }
    }
    std::env::var("HOME").unwrap_or_else(|_| "/root".to_string())
}

/// Installa e abilita il servizio systemd: il client parte al boot. Con
/// `as_exit` il servizio fa da exit node; altrimenti si limita a connettersi.
#[cfg(target_os = "linux")]
fn install_service(as_exit: bool) -> Result<(), Box<dyn std::error::Error>> {
    let exe = std::env::current_exe()?;
    let home = real_home();
    // Verifica che ci sia già un'identità salvata (login fatto).
    let cfg = PathBuf::from(&home).join(".p2p-holepunch").join("config.json");
    if !cfg.exists() {
        eprintln!("[Servizio] ⚠ Nessuna identità in {}.", cfg.display());
        eprintln!("[Servizio]   Esegui prima il login: `{} \"nome-device\"` e approva dal browser.", exe.display());
    }
    let role = if as_exit { " --exit-node" } else { "" };
    let unit = format!(
        "[Unit]\n\
         Description=P2P VPN client (connessione all'avvio)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\n\
         [Service]\n\
         Type=simple\n\
         Environment=HOME={home}\n\
         ExecStart={exe}{role}\n\
         Restart=always\n\
         RestartSec=5\n\
         User=root\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        home = home,
        exe = exe.display(),
        role = role,
    );
    let path = format!("/etc/systemd/system/{SERVICE_NAME}.service");
    std::fs::write(&path, unit).map_err(|e| format!("scrittura {path} fallita (serve sudo?): {e}"))?;
    println!("[Servizio] Unit scritta in {path}");
    let run = |args: &[&str]| {
        let ok = std::process::Command::new("systemctl")
            .args(args)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        println!("[Servizio] systemctl {} → {}", args.join(" "), if ok { "ok" } else { "FALLITO" });
    };
    run(&["daemon-reload"]);
    run(&["enable", "--now", SERVICE_NAME]);
    println!("[Servizio] ✅ Attivo. Stato: `systemctl status {SERVICE_NAME}` · Log: `journalctl -u {SERVICE_NAME} -f`");
    Ok(())
}

/// Disabilita e rimuove il servizio systemd.
#[cfg(target_os = "linux")]
fn uninstall_service() -> Result<(), Box<dyn std::error::Error>> {
    let run = |args: &[&str]| {
        let _ = std::process::Command::new("systemctl").args(args).status();
    };
    run(&["disable", "--now", SERVICE_NAME]);
    let path = format!("/etc/systemd/system/{SERVICE_NAME}.service");
    let _ = std::fs::remove_file(&path);
    run(&["daemon-reload"]);
    println!("[Servizio] ✅ Rimosso ({path}).");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn install_service(_as_exit: bool) -> Result<(), Box<dyn std::error::Error>> {
    Err("La connessione all'avvio (servizio systemd) è disponibile solo su Linux (es. Raspberry Pi).".into())
}

#[cfg(not(target_os = "linux"))]
fn uninstall_service() -> Result<(), Box<dyn std::error::Error>> {
    Err("La connessione all'avvio (servizio systemd) è disponibile solo su Linux (es. Raspberry Pi).".into())
}

