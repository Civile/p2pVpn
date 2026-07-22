//! # Data plane VPN (exit node) — feature `vpn`
//!
//! Trasporta pacchetti IP reali sopra il socket UDP **già bucato** dalla mesh
//! (hole punching), così un dispositivo può instradare il proprio traffico
//! attraverso un altro marcato come *exit node*.
//!
//! Schema (subnet virtuale `10.7.0.0/24`):
//! ```text
//!   client (TUN 10.7.0.x, default route → TUN)
//!      │  pacchetti IP incapsulati su UDP (magic byte)
//!      ▼
//!   exit node (TUN 10.7.0.1, IP forwarding + NAT masquerade)
//!      │  esce verso Internet, torna, viene de-NATtato
//!      ▼  rispedito al client giusto (mappa vip → indirizzo UDP)
//! ```
//!
//! ## Stato / verifica
//! Il **framing** e la **demultiplazione** sono coperti da unit test. Le parti
//! che aprono la TUN e configurano routing/NAT richiedono privilegi **root** e
//! un host reale (tipicamente Linux per l'uscita): **non sono verificabili**
//! nell'ambiente di sviluppo. Vedi `EXIT-NODE.md` per il runbook.
//!
//! ## Limiti di questo primo taglio
//! - Nessuna cifratura del tunnel (va aggiunta prima dell'uso reale: WireGuard).
//! - IP virtuale del client derivato dall'hash del `device_id` (possibili
//!   collisioni con molti client sullo stesso exit; per una vera tailnet serve
//!   un IPAM nel control plane).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::proto::relay;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::time::sleep;

/// Byte iniziale che distingue un pacchetto VPN da un PING di hole punching o
/// da un ack del server. Scelto fuori dal range ASCII stampabile dei PING.
pub const VPN_MAGIC: u8 = 0x76; // 'v'

/// Subnet virtuale del tunnel.
pub const TUN_NETMASK: [u8; 4] = [255, 255, 255, 0];
/// MTU dell'interfaccia TUN (lascia spazio per WireGuard + relay + UDP/IP).
pub const TUN_MTU: u16 = 1280;
/// Indirizzo TUN dell'exit node.
pub const EXIT_VIP: Ipv4Addr = Ipv4Addr::new(10, 7, 0, 1);

// ----------------------------------------------------------------- framing ---

/// Incapsula un pacchetto IP in un datagramma UDP del tunnel.
pub fn encap(ip_packet: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(ip_packet.len() + 1);
    v.push(VPN_MAGIC);
    v.extend_from_slice(ip_packet);
    v
}

/// Estrae il pacchetto IP da un datagramma del tunnel, se ha il magic corretto.
pub fn decap(datagram: &[u8]) -> Option<&[u8]> {
    match datagram.split_first() {
        Some((&VPN_MAGIC, rest)) => Some(rest),
        _ => None,
    }
}

/// `true` se il datagramma è traffico VPN (non un PING/ack di hole punching).
pub fn is_vpn(datagram: &[u8]) -> bool {
    datagram.first() == Some(&VPN_MAGIC)
}

// -------------------------------------------------------------- endpoint ---
//
// Un peer del tunnel è raggiungibile in due modi, trasparenti al data plane:
//   • `Direct`  — datagrammi WireGuard spediti direttamente al suo IP:porta
//                 (hole punching riuscito, LAN, o port forwarding).
//   • `Relay`   — spediti al server, che li inoltra al peer (stile DERP). È il
//                 default: funziona ovunque, anche dietro CGNAT/NAT simmetrico.
//
// Le sessioni WireGuard sono indicizzate per `Endpoint` (identità del peer), non
// per l'indirizzo di trasporto: così i pacchetti che arrivano tutti dal relay
// non collassano su un'unica sessione.

/// Come raggiungere un peer del tunnel.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Endpoint {
    /// Invio diretto all'endpoint del peer.
    Direct(SocketAddr),
    /// Invio tramite relay sul server: `peer` è il `device_id` di destinazione.
    Relay { relay: SocketAddr, peer: String },
}

impl Endpoint {
    /// L'IP verso cui viaggiano davvero i datagrammi WireGuard (endpoint diretto
    /// o server relay). È l'IP da tenere fuori dal full tunnel (rotta host).
    pub fn wire_ip(&self) -> IpAddr {
        match self {
            Endpoint::Direct(a) => a.ip(),
            Endpoint::Relay { relay, .. } => relay.ip(),
        }
    }

    /// Serializza un datagramma WireGuard per questo endpoint e restituisce
    /// `(bytes, destinazione)` pronti per `send_to`.
    fn frame(&self, wg: &[u8]) -> (Vec<u8>, SocketAddr) {
        match self {
            Endpoint::Direct(a) => (encap(wg), *a),
            Endpoint::Relay { relay, peer } => (relay::wrap(peer, wg), *relay),
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Endpoint::Direct(a) => write!(f, "diretto {a}"),
            Endpoint::Relay { relay, peer } => write!(f, "relay {relay} → {}…", &peer[..peer.len().min(8)]),
        }
    }
}

/// Invia un datagramma WireGuard grezzo verso `ep` (diretto o via relay).
async fn send_wg(udp: &UdpSocket, ep: &Endpoint, wg: &[u8]) {
    let (bytes, dst) = ep.frame(wg);
    let _ = udp.send_to(&bytes, dst).await;
}

/// IP virtuale deterministico di un client a partire dal suo `device_id`.
/// Mappa nell'intervallo `10.7.0.2 ..= 10.7.0.254`.
pub fn client_vip(device_id: &str) -> Ipv4Addr {
    let mut h: u32 = 2166136261;
    for b in device_id.bytes() {
        h = (h ^ b as u32).wrapping_mul(16777619);
    }
    let host = 2 + (h % 253) as u8; // 2..=254
    Ipv4Addr::new(10, 7, 0, host)
}

/// IP di destinazione (IPv4) di un pacchetto IP grezzo, se presente.
fn ipv4_dst(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() >= 20 && (pkt[0] >> 4) == 4 {
        Some(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
    } else {
        None
    }
}

/// IP sorgente (IPv4) di un pacchetto IP grezzo, se presente.
fn ipv4_src(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() >= 20 && (pkt[0] >> 4) == 4 {
        Some(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]))
    } else {
        None
    }
}

// -------------------------------------------------------------- crypto ---
//
// Cifratura del tunnel con WireGuard userspace (boringtun). Ogni coppia
// client↔exit ha una sessione `Tunn` con handshake Noise + cifratura ChaCha20.

pub mod crypto {
    use base64::Engine;
    use boringtun::noise::Tunn;
    pub use boringtun::x25519::{PublicKey, StaticSecret};

    /// Genera una coppia di chiavi X25519 (privata, pubblica).
    pub fn gen_keypair() -> (StaticSecret, PublicKey) {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("getrandom");
        let sk = StaticSecret::from(bytes);
        let pk = PublicKey::from(&sk);
        (sk, pk)
    }

    pub fn pk_to_b64(pk: &PublicKey) -> String {
        base64::engine::general_purpose::STANDARD.encode(pk.as_bytes())
    }
    pub fn sk_to_b64(sk: &StaticSecret) -> String {
        base64::engine::general_purpose::STANDARD.encode(sk.to_bytes())
    }
    fn from_b64_32(s: &str) -> Option<[u8; 32]> {
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .ok()?
            .try_into()
            .ok()
    }
    pub fn sk_from_b64(s: &str) -> Option<StaticSecret> {
        Some(StaticSecret::from(from_b64_32(s)?))
    }
    pub fn pk_from_b64(s: &str) -> Option<PublicKey> {
        Some(PublicKey::from(from_b64_32(s)?))
    }

    /// Crea una sessione WireGuard verso un peer.
    pub fn new_tunn(my_secret: &StaticSecret, peer_public: &PublicKey, index: u32) -> Box<Tunn> {
        Box::new(Tunn::new(my_secret.clone(), *peer_public, None, None, index, None))
    }
}

// --------------------------------------------------- demux dei datagrammi ---
//
// Il socket UDP è uno solo (quello bucato dalla mesh) e viene letto da un unico
// ricevitore nel client. Quando la feature `vpn` è attiva, i datagrammi VPN
// vanno consegnati qui invece di essere stampati come PING.

static VPN_INBOUND: Mutex<Option<UnboundedSender<(Endpoint, Vec<u8>)>>> = Mutex::new(None);

/// Registra il canale su cui il ricevitore consegnerà i pacchetti VPN in arrivo.
fn register_inbound() -> UnboundedReceiver<(Endpoint, Vec<u8>)> {
    let (tx, rx) = mpsc::unbounded_channel();
    *VPN_INBOUND.lock().unwrap() = Some(tx);
    rx
}

/// Consegna un datagramma WireGuard in arrivo al tunnel (chiamata dal
/// ricevitore), etichettato con l'`Endpoint` da cui proviene (diretto o relay).
/// Ritorna `true` se un tunnel era in ascolto.
pub fn deliver_inbound(from: Endpoint, wg_datagram: Vec<u8>) -> bool {
    match &*VPN_INBOUND.lock().unwrap() {
        Some(tx) => tx.send((from, wg_datagram)).is_ok(),
        None => false,
    }
}

// --------------------------------------------------- sessioni WireGuard ---

use boringtun::noise::{Tunn, TunnResult};

/// Sessione WireGuard condivisa tra i task (TUN, rete, timer).
type Session = Arc<tokio::sync::Mutex<Box<Tunn>>>;

fn new_session(my_sk: &crypto::StaticSecret, peer_pk: &crypto::PublicKey, index: u32) -> Session {
    Arc::new(tokio::sync::Mutex::new(crypto::new_tunn(my_sk, peer_pk, index)))
}

/// Cifra un pacchetto IP → datagramma WireGuard da spedire in rete.
/// Con `ip_packet` vuoto forza l'invio dell'handshake iniziale (senza dati).
async fn wg_encapsulate(sess: &Session, ip_packet: &[u8]) -> Option<Vec<u8>> {
    let mut t = sess.lock().await;
    // Buffer ampio: l'handshake init è ~148 byte, più dei dati incapsulati.
    let mut buf = vec![0u8; ip_packet.len() + 160];
    match t.encapsulate(ip_packet, &mut buf) {
        TunnResult::WriteToNetwork(d) => Some(d.to_vec()),
        _ => None,
    }
}

/// Decapsula un datagramma WireGuard → (pacchetto in chiaro per il TUN,
/// datagrammi da rispedire in rete: risposte di handshake/keepalive).
async fn wg_decapsulate(sess: &Session, datagram: &[u8]) -> (Option<Vec<u8>>, Vec<Vec<u8>>) {
    let mut t = sess.lock().await;
    let mut net = Vec::new();
    let mut plain = None;
    let mut buf = vec![0u8; 2048];
    match t.decapsulate(None, datagram, &mut buf) {
        TunnResult::WriteToNetwork(d) => {
            net.push(d.to_vec());
            loop {
                let mut fb = vec![0u8; 2048];
                match t.decapsulate(None, &[], &mut fb) {
                    TunnResult::WriteToNetwork(d) => net.push(d.to_vec()),
                    _ => break,
                }
            }
        }
        TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
            plain = Some(p.to_vec());
        }
        _ => {}
    }
    (plain, net)
}

/// `true` se un handshake WireGuard è stato completato almeno una volta (la
/// sessione è cifrata e pronta): usato per decidere quando è sicuro dirottare
/// tutto il traffico nel tunnel (full tunnel).
async fn wg_handshake_done(sess: &Session) -> bool {
    sess.lock().await.time_since_last_handshake().is_some()
}

/// Aggiorna i timer WireGuard (handshake/keepalive/rekey). Ritorna eventuali
/// datagrammi da spedire.
async fn wg_tick(sess: &Session) -> Vec<Vec<u8>> {
    let mut t = sess.lock().await;
    let mut buf = vec![0u8; 2048];
    match t.update_timers(&mut buf) {
        TunnResult::WriteToNetwork(d) => vec![d.to_vec()],
        _ => vec![],
    }
}

// ---------------------------------------------------------- tunnel client ---

/// Avvia il tunnel **client** cifrato verso l'exit node. Richiede root.
///
/// Con `full_tunnel = true` dirotta **tutto** il traffico del sistema dentro il
/// tunnel (VPN reale) non appena l'handshake WireGuard è confermato; con
/// `false` crea solo l'interfaccia TUN (routing lasciato all'utente).
pub fn spawn_client_tunnel(
    udp: Arc<UdpSocket>,
    exit_ep: Endpoint,
    my_sk_b64: String,
    exit_pk_b64: String,
    my_vip: Ipv4Addr,
    full_tunnel: bool,
) {
    let inbound = register_inbound();
    tokio::spawn(async move {
        if let Err(e) =
            run_client_tunnel(udp, exit_ep, my_sk_b64, exit_pk_b64, my_vip, full_tunnel, inbound).await
        {
            eprintln!("[vpn/client] errore: {e}");
        }
    });
}

async fn run_client_tunnel(
    udp: Arc<UdpSocket>,
    exit_ep: Endpoint,
    my_sk_b64: String,
    exit_pk_b64: String,
    my_vip: Ipv4Addr,
    full_tunnel: bool,
    mut inbound: UnboundedReceiver<(Endpoint, Vec<u8>)>,
) -> Result<(), String> {
    let my_sk = crypto::sk_from_b64(&my_sk_b64).ok_or("chiave privata non valida")?;
    let exit_pk = crypto::pk_from_b64(&exit_pk_b64).ok_or("chiave pubblica dell'exit non valida")?;
    let sess = new_session(&my_sk, &exit_pk, 1);
    println!("[vpn/client] TUN {my_vip}/24 · uscita CIFRATA (WireGuard) via {exit_ep}");

    let dev = open_tun(my_vip).map_err(|e| e.to_string())?;
    let (mut tun_r, tun_w) = tokio::io::split(dev);
    let tun_w = Arc::new(tokio::sync::Mutex::new(tun_w));

    // Avvia SUBITO l'handshake, senza aspettare traffico dalla TUN: incapsulando
    // un pacchetto vuoto boringtun emette l'handshake initiation. Senza questo
    // kick si crea uno stallo (niente traffico → niente handshake → niente
    // routing → niente traffico).
    if let Some(dg) = wg_encapsulate(&sess, &[]).await {
        send_wg(&udp, &exit_ep, &dg).await;
        println!("[vpn/client] handshake WireGuard avviato verso {exit_ep}…");
    }

    // Mantieni i timer (ritrasmissioni handshake, keepalive, rekey).
    {
        let sess = sess.clone();
        let udp = udp.clone();
        let exit_ep = exit_ep.clone();
        tokio::spawn(async move {
            loop {
                for dg in wg_tick(&sess).await {
                    send_wg(&udp, &exit_ep, &dg).await;
                }
                sleep(Duration::from_millis(250)).await;
            }
        });
    }

    // TUN → cifra → UDP verso l'exit.
    {
        let sess = sess.clone();
        let udp = udp.clone();
        let exit_ep = exit_ep.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let n = match tun_r.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if let Some(dg) = wg_encapsulate(&sess, &buf[..n]).await {
                    send_wg(&udp, &exit_ep, &dg).await;
                }
            }
        });
    }

    // UDP (dal demux) → decifra → TUN (e rispedisci le risposte di handshake).
    // Quando l'handshake è confermato, se richiesto attiviamo il full tunnel
    // (routing di tutto il traffico dentro il TUN) — una sola volta.
    let mut routed = false;
    let mut got_inbound = false;
    while let Some((_from, dg)) = inbound.recv().await {
        if !got_inbound {
            got_inbound = true;
            println!("[vpn/client] primo pacchetto cifrato ricevuto dall'exit ({} byte) — ritorno OK", dg.len());
        }
        let (plain, net) = wg_decapsulate(&sess, &dg).await;
        for r in net {
            send_wg(&udp, &exit_ep, &r).await;
        }
        if let Some(p) = plain {
            let mut w = tun_w.lock().await;
            let _ = w.write_all(&p).await;
        }
        if full_tunnel && !routed && wg_handshake_done(&sess).await {
            routed = true;
            // Teniamo raggiungibile per la sua strada normale l'IP verso cui
            // spediamo davvero i pacchetti WireGuard: l'exit se diretto, oppure
            // il server relay. Così quei pacchetti non rientrano nel tunnel.
            match exit_ep.wire_ip() {
                IpAddr::V4(wire_ip) => {
                    println!("[vpn/client] handshake OK → attivo il full tunnel (VPN reale)…");
                    if let Err(e) = crate::route::apply_full_tunnel(wire_ip, my_vip) {
                        eprintln!("[vpn/client] routing full tunnel non riuscito: {e}");
                        eprintln!("[vpn/client] la rete è intatta; instrada a mano (vedi EXIT-NODE.md).");
                    }
                }
                IpAddr::V6(_) => {
                    eprintln!("[vpn/client] full tunnel non supportato su endpoint IPv6.");
                }
            }
        }
    }
    Ok(())
}

// ------------------------------------------------------------ tunnel exit ---
//
// L'exit node tiene una sessione WireGuard **per client** (indicizzata dal suo
// endpoint UDP). Le chiavi pubbliche dei client vengono registrate da chi
// avvia il nodo, man mano che arrivano dai `PeerInfo` della mesh.

/// Registro delle chiavi pubbliche dei peer, per l'exit node: endpoint → pubkey.
static EXIT_PEER_KEYS: Mutex<Vec<(SocketAddr, String)>> = Mutex::new(Vec::new());
/// Chiave privata dell'exit node (base64).
static EXIT_MY_SK: Mutex<Option<String>> = Mutex::new(None);

/// Registra la chiave pubblica di un possibile client dell'exit node.
pub fn exit_add_peer(addr: SocketAddr, pk_b64: String) {
    let mut v = EXIT_PEER_KEYS.lock().unwrap();
    if let Some(slot) = v.iter_mut().find(|(a, _)| *a == addr) {
        slot.1 = pk_b64;
    } else {
        v.push((addr, pk_b64));
    }
}

/// Tutte le chiavi pubbliche note dei client (senza duplicati). Serve all'exit
/// per identificare il client anche quando l'indirizzo UDP da cui arriva
/// l'handshake non combacia con quello annunciato dal server (NAT).
fn all_peer_keys() -> Vec<String> {
    let mut v: Vec<String> =
        EXIT_PEER_KEYS.lock().unwrap().iter().map(|(_, k)| k.clone()).collect();
    v.sort();
    v.dedup();
    v
}

/// Avvia il tunnel lato **exit node**: decifra i pacchetti dei client, li
/// inoltra a Internet (IP forwarding + NAT) e rispedisce cifrate le risposte al
/// client corretto. Richiede root.
pub fn spawn_exit_node(udp: Arc<UdpSocket>, my_sk_b64: String, my_vip: Ipv4Addr) {
    *EXIT_MY_SK.lock().unwrap() = Some(my_sk_b64);
    let inbound = register_inbound();
    tokio::spawn(async move {
        if let Err(e) = run_exit_node(udp, my_vip, inbound).await {
            eprintln!("[vpn/exit] errore: {e}");
        }
    });
}

async fn run_exit_node(
    udp: Arc<UdpSocket>,
    my_vip: Ipv4Addr,
    mut inbound: UnboundedReceiver<(Endpoint, Vec<u8>)>,
) -> Result<(), String> {
    let my_sk_b64 = EXIT_MY_SK.lock().unwrap().clone().ok_or("chiave privata mancante")?;
    let my_sk = crypto::sk_from_b64(&my_sk_b64).ok_or("chiave privata non valida")?;
    println!("[vpn/exit] TUN {my_vip}/24 · uscita CIFRATA (WireGuard)");
    let dev = open_tun(my_vip).map_err(|e| e.to_string())?;
    configure_exit_nat();
    let (mut tun_r, tun_w) = tokio::io::split(dev);
    let tun_w = Arc::new(tokio::sync::Mutex::new(tun_w));

    // Sessione per client (per Endpoint) e mappa IP virtuale → Endpoint client.
    let sessions: Arc<tokio::sync::Mutex<HashMap<Endpoint, Session>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let routes: Arc<Mutex<HashMap<Ipv4Addr, Endpoint>>> = Arc::new(Mutex::new(HashMap::new()));

    // TUN (risposte da Internet, de-NATtate) → cifra → UDP verso il client giusto.
    {
        let sessions = sessions.clone();
        let routes = routes.clone();
        let udp = udp.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let n = match tun_r.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let Some(dst) = ipv4_dst(&buf[..n]) else { continue };
                let ep = routes.lock().unwrap().get(&dst).cloned();
                let Some(ep) = ep else { continue };
                let sess = sessions.lock().await.get(&ep).cloned();
                if let Some(sess) = sess {
                    if let Some(dg) = wg_encapsulate(&sess, &buf[..n]).await {
                        send_wg(&udp, &ep, &dg).await;
                    }
                }
            }
        });
    }

    // Timer di tutte le sessioni.
    {
        let sessions = sessions.clone();
        let udp = udp.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_millis(250)).await;
                let all: Vec<(Endpoint, Session)> =
                    sessions.lock().await.iter().map(|(a, s)| (a.clone(), s.clone())).collect();
                for (ep, s) in all {
                    for dg in wg_tick(&s).await {
                        send_wg(&udp, &ep, &dg).await;
                    }
                }
            }
        });
    }

    let mut index: u32 = 100;
    // UDP (dai client, via demux) → decifra → impara la rotta → TUN → Internet.
    while let Some((ep, dg)) = inbound.recv().await {
        // Sessione già nota per questo Endpoint?
        let existing = sessions.lock().await.get(&ep).cloned();
        let sess = match existing {
            Some(s) => s,
            None => {
                // Client nuovo: prova tutte le chiavi note finché una decifra
                // davvero questo datagramma (gestisce anche il caso in cui l'IP
                // di provenienza non combacia con quello annunciato dal server).
                let keys = all_peer_keys();
                println!("[vpn/exit] datagramma VPN da {ep}: provo {} chiavi note", keys.len());
                let mut chosen: Option<Session> = None;
                for k in keys {
                    let Some(pk) = crypto::pk_from_b64(&k) else { continue };
                    index += 1;
                    let candidate = new_session(&my_sk, &pk, index);
                    let (plain, net) = wg_decapsulate(&candidate, &dg).await;
                    if !net.is_empty() || plain.is_some() {
                        // Chiave giusta: registra la sessione e gestisci l'output.
                        sessions.lock().await.insert(ep.clone(), candidate.clone());
                        println!("[vpn/exit] sessione WireGuard avviata con client {ep}");
                        for r in net {
                            send_wg(&udp, &ep, &r).await;
                        }
                        if let Some(p) = plain {
                            if let Some(vip) = ipv4_src(&p) {
                                routes.lock().unwrap().insert(vip, ep.clone());
                            }
                            let mut w = tun_w.lock().await;
                            let _ = w.write_all(&p).await;
                        }
                        chosen = Some(candidate);
                        break;
                    }
                }
                if chosen.is_none() {
                    // Nessuna chiave nota decifra: la chiave del client non è
                    // ancora arrivata dal server. Riproverà al prossimo pacchetto.
                    println!("[vpn/exit] nessuna chiave nota decifra il datagramma da {ep} (client non ancora annunciato dal server?)");
                    continue;
                }
                continue; // datagramma già gestito qui sopra
            }
        };
        // Sessione esistente: percorso normale.
        let (plain, net) = wg_decapsulate(&sess, &dg).await;
        for r in net {
            send_wg(&udp, &ep, &r).await;
        }
        if let Some(p) = plain {
            if let Some(vip) = ipv4_src(&p) {
                routes.lock().unwrap().insert(vip, ep.clone());
            }
            let mut w = tun_w.lock().await;
            let _ = w.write_all(&p).await;
        }
    }
    Ok(())
}

/// Abilita IP forwarding + NAT masquerade sull'exit node (Linux). Best-effort:
/// se un comando fallisce (permessi, non-Linux) lo segnala e prosegue. Vedi
/// `EXIT-NODE.md` per l'equivalente manuale e per macOS (pf).
fn configure_exit_nat() {
    #[cfg(target_os = "linux")]
    {
        let run = |args: &[&str]| {
            let ok = std::process::Command::new(args[0])
                .args(&args[1..])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            println!("[vpn/exit] {} → {}", args.join(" "), if ok { "ok" } else { "FALLITO" });
        };
        run(&["sysctl", "-w", "net.ipv4.ip_forward=1"]);
        // Idempotente: prima cancella una regola gemella, poi la aggiunge.
        let _ = std::process::Command::new("iptables")
            .args(["-t", "nat", "-D", "POSTROUTING", "-s", "10.7.0.0/24", "-j", "MASQUERADE"])
            .status();
        run(&["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.7.0.0/24", "-j", "MASQUERADE"]);
    }
    #[cfg(not(target_os = "linux"))]
    {
        println!("[vpn/exit] NAT automatico non configurato su questo OS: vedi EXIT-NODE.md (macOS: pfctl).");
    }
}

/// Crea e configura l'interfaccia TUN con l'indirizzo `vip`.
fn open_tun(vip: Ipv4Addr) -> std::io::Result<tun::AsyncDevice> {
    let mut config = tun::Configuration::default();
    config
        .address(vip)
        .netmask(Ipv4Addr::from(TUN_NETMASK))
        // MTU contenuta: il payload viene incapsulato in WireGuard e (via relay)
        // di nuovo in UDP verso il server. 1280 lascia margine abbondante per gli
        // header ed evita frammentazione/perdite sul percorso relay.
        .mtu(TUN_MTU)
        .up();
    tun::create_as_async(&config)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
}

// ------------------------------------------------------------------ test ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encap_decap_roundtrip() {
        let pkt = [0x45u8, 0, 0, 20, 1, 2, 3, 4]; // finto header IPv4
        let dg = encap(&pkt);
        assert_eq!(dg[0], VPN_MAGIC);
        assert!(is_vpn(&dg));
        assert_eq!(decap(&dg), Some(&pkt[..]));
    }

    #[test]
    fn hole_punch_is_not_vpn() {
        let ping = b"PING #1 (hole-punch)";
        assert!(!is_vpn(ping));
        assert_eq!(decap(ping), None);
    }

    #[test]
    fn vip_in_range_and_stable() {
        for id in ["laptop", "telefono", "nas-casa", "abc123", ""] {
            let ip = client_vip(id);
            let o = ip.octets();
            assert_eq!([o[0], o[1], o[2]], [10, 7, 0]);
            assert!(o[3] >= 2 && o[3] <= 254, "octet {} fuori range", o[3]);
            assert_eq!(client_vip(id), ip, "deve essere deterministico");
        }
    }

    #[test]
    fn wireguard_handshake_and_roundtrip() {
        use super::crypto::*;
        use boringtun::noise::{Tunn, TunnResult};

        let (a_sk, a_pk) = gen_keypair();
        let (b_sk, b_pk) = gen_keypair();
        let mut a = new_tunn(&a_sk, &b_pk, 1);
        let mut b = new_tunn(&b_sk, &a_pk, 2);

        // Pacchetto IPv4 valido (header con total-length corretto: boringtun usa
        // quel campo per sapere quanti byte cifrare).
        let mut payload = vec![0u8; 40];
        payload[0] = 0x45; // versione 4, IHL 5
        payload[2..4].copy_from_slice(&(40u16).to_be_bytes()); // total length
        payload[12..16].copy_from_slice(&[10, 7, 0, 2]); // src
        payload[16..20].copy_from_slice(&[10, 7, 0, 1]); // dst

        // Consegna un datagramma a un Tunn; accumula le risposte di rete
        // (drenando la coda interna) e cattura l'eventuale pacchetto in chiaro.
        fn deliver(t: &mut Tunn, dg: &[u8], net_out: &mut Vec<Vec<u8>>, received: &mut Option<Vec<u8>>) {
            let mut buf = [0u8; 2048];
            match t.decapsulate(None, dg, &mut buf) {
                TunnResult::WriteToNetwork(d) => {
                    net_out.push(d.to_vec());
                    loop {
                        let mut fb = [0u8; 2048];
                        match t.decapsulate(None, &[], &mut fb) {
                            TunnResult::WriteToNetwork(d) => net_out.push(d.to_vec()),
                            _ => break,
                        }
                    }
                }
                TunnResult::WriteToTunnelV4(p, _) => {
                    if !p.is_empty() {
                        *received = Some(p.to_vec());
                    }
                }
                _ => {}
            }
        }

        let mut received: Option<Vec<u8>> = None;
        let mut cipher_seen = false;
        let mut a2b: Vec<Vec<u8>> = Vec::new();
        let mut b2a: Vec<Vec<u8>> = Vec::new();

        // A prova a inviare → handshake init.
        let mut buf = [0u8; 2048];
        if let TunnResult::WriteToNetwork(d) = a.encapsulate(&payload, &mut buf) {
            a2b.push(d.to_vec());
        }

        for _ in 0..20 {
            for m in std::mem::take(&mut a2b) {
                deliver(&mut b, &m, &mut b2a, &mut received);
            }
            for m in std::mem::take(&mut b2a) {
                deliver(&mut a, &m, &mut a2b, &mut received);
            }
            if received.is_some() {
                break;
            }
            // Ristabilito l'handshake, questo invio produce il datagramma cifrato.
            let mut buf = [0u8; 2048];
            if let TunnResult::WriteToNetwork(d) = a.encapsulate(&payload, &mut buf) {
                if d.len() >= payload.len() {
                    cipher_seen = true;
                }
                a2b.push(d.to_vec());
            }
        }

        assert!(cipher_seen, "deve esserci traffico cifrato sulla rete");
        assert_eq!(received.as_deref(), Some(&payload[..]), "B deve recuperare il pacchetto in chiaro");
    }

    /// End-to-end del **percorso relay**: due sessioni WireGuard completano
    /// l'handshake e si scambiano un pacchetto passando *solo* dal relay (nessun
    /// invio diretto), su socket UDP reali (loopback). Verifica che framing,
    /// riscrittura del mittente (`Table::route`) e sessioni-per-identità
    /// compongano correttamente — la parte che non richiede TUN/root.
    #[tokio::test]
    async fn wireguard_handshake_over_relay() {
        use crate::proto::relay;
        use boringtun::noise::TunnResult;
        use std::sync::Arc;
        use tokio::net::UdpSocket;

        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();

        // Relay: tabella precompilata (come dopo i keepalive) + loop di inoltro.
        let mut table = relay::Table::default();
        table.upsert("A", a.local_addr().unwrap());
        table.upsert("B", b.local_addr().unwrap());
        let table = Arc::new(std::sync::Mutex::new(table));
        {
            let (server, table) = (server.clone(), table.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                loop {
                    let (n, src) = server.recv_from(&mut buf).await.unwrap();
                    let out = table.lock().unwrap().route(src, &buf[..n]);
                    if let Some((bytes, dst)) = out {
                        let _ = server.send_to(&bytes, dst).await;
                    }
                }
            });
        }

        let (a_sk, a_pk) = crypto::gen_keypair();
        let (b_sk, b_pk) = crypto::gen_keypair();

        // Pacchetto IPv4 valido di prova (boringtun cifra fino a total-length).
        let mut payload = vec![0u8; 40];
        payload[0] = 0x45;
        payload[2..4].copy_from_slice(&(40u16).to_be_bytes());
        payload[12..16].copy_from_slice(&[10, 7, 0, 2]);
        payload[16..20].copy_from_slice(&[10, 7, 0, 1]);
        let expected = payload.clone();

        // Exit "B": decifra i frame; sul pacchetto in chiaro segnala via canale.
        // Le risposte di rete tornano al mittente letto dal frame (riscritto ad "A").
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        {
            let b = b.clone();
            let mut tun = crypto::new_tunn(&b_sk, &a_pk, 2);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                loop {
                    let (n, _src) = b.recv_from(&mut buf).await.unwrap();
                    let Some((peer_id, wg)) = relay::parse(&buf[..n]) else { continue };
                    let peer_id = peer_id.to_string();
                    let mut out = vec![0u8; 2048];
                    match tun.decapsulate(None, wg, &mut out) {
                        TunnResult::WriteToNetwork(d) => {
                            let _ = b.send_to(&relay::wrap(&peer_id, d), server_addr).await;
                            loop {
                                let mut fb = vec![0u8; 2048];
                                match tun.decapsulate(None, &[], &mut fb) {
                                    TunnResult::WriteToNetwork(d) => {
                                        let _ = b.send_to(&relay::wrap(&peer_id, d), server_addr).await;
                                    }
                                    _ => break,
                                }
                            }
                        }
                        TunnResult::WriteToTunnelV4(p, _) => {
                            let _ = tx.send(p.to_vec());
                        }
                        _ => {}
                    }
                }
            });
        }

        // Client "A": avvia l'handshake e, una volta stabilito, invia il payload.
        {
            let a = a.clone();
            let mut tun = crypto::new_tunn(&a_sk, &b_pk, 1);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                if let TunnResult::WriteToNetwork(d) = tun.encapsulate(&[], &mut buf) {
                    let _ = a.send_to(&relay::wrap("B", d), server_addr).await;
                }
                let mut sent_data = false;
                let mut rbuf = vec![0u8; 2048];
                loop {
                    let (n, _src) = a.recv_from(&mut rbuf).await.unwrap();
                    let Some((_peer, wg)) = relay::parse(&rbuf[..n]) else { continue };
                    let mut out = vec![0u8; 2048];
                    if let TunnResult::WriteToNetwork(d) = tun.decapsulate(None, wg, &mut out) {
                        let _ = a.send_to(&relay::wrap("B", d), server_addr).await;
                    }
                    if !sent_data && tun.time_since_last_handshake().is_some() {
                        sent_data = true;
                        let mut eb = vec![0u8; 2048];
                        if let TunnResult::WriteToNetwork(d) = tun.encapsulate(&payload, &mut eb) {
                            let _ = a.send_to(&relay::wrap("B", d), server_addr).await;
                        }
                    }
                }
            });
        }

        let got = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout: handshake via relay non completato")
            .expect("canale chiuso");
        assert_eq!(got, expected, "B deve ricevere in chiaro il payload di A, passando dal relay");
    }

    #[test]
    fn key_base64_roundtrip() {
        use super::crypto::*;
        let (sk, pk) = gen_keypair();
        let pk2 = pk_from_b64(&pk_to_b64(&pk)).unwrap();
        assert_eq!(pk.as_bytes(), pk2.as_bytes());
        let sk2 = sk_from_b64(&sk_to_b64(&sk)).unwrap();
        assert_eq!(sk.to_bytes(), sk2.to_bytes());
    }

    #[test]
    fn parses_ipv4_src_dst() {
        // header IPv4 minimale: src 10.7.0.9, dst 8.8.8.8
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[12..16].copy_from_slice(&[10, 7, 0, 9]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        assert_eq!(ipv4_src(&pkt), Some(Ipv4Addr::new(10, 7, 0, 9)));
        assert_eq!(ipv4_dst(&pkt), Some(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(ipv4_dst(&[0x45]), None); // troppo corto
    }
}
