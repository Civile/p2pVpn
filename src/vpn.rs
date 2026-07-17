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
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::time::sleep;

/// Byte iniziale che distingue un pacchetto VPN da un PING di hole punching o
/// da un ack del server. Scelto fuori dal range ASCII stampabile dei PING.
pub const VPN_MAGIC: u8 = 0x76; // 'v'

/// Subnet virtuale del tunnel.
pub const TUN_NETMASK: [u8; 4] = [255, 255, 255, 0];
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

static VPN_INBOUND: Mutex<Option<UnboundedSender<(SocketAddr, Vec<u8>)>>> = Mutex::new(None);

/// Registra il canale su cui il ricevitore consegnerà i pacchetti VPN in arrivo.
fn register_inbound() -> UnboundedReceiver<(SocketAddr, Vec<u8>)> {
    let (tx, rx) = mpsc::unbounded_channel();
    *VPN_INBOUND.lock().unwrap() = Some(tx);
    rx
}

/// Consegna un datagramma VPN in arrivo al tunnel (chiamata dal ricevitore).
/// Ritorna `true` se un tunnel era in ascolto.
pub fn deliver_inbound(src: SocketAddr, ip_packet: Vec<u8>) -> bool {
    match &*VPN_INBOUND.lock().unwrap() {
        Some(tx) => tx.send((src, ip_packet)).is_ok(),
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
async fn wg_encapsulate(sess: &Session, ip_packet: &[u8]) -> Option<Vec<u8>> {
    let mut t = sess.lock().await;
    let mut buf = vec![0u8; ip_packet.len() + 64];
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
pub fn spawn_client_tunnel(
    udp: Arc<UdpSocket>,
    exit_addr: SocketAddr,
    my_sk_b64: String,
    exit_pk_b64: String,
    my_vip: Ipv4Addr,
) {
    let inbound = register_inbound();
    tokio::spawn(async move {
        if let Err(e) = run_client_tunnel(udp, exit_addr, my_sk_b64, exit_pk_b64, my_vip, inbound).await {
            eprintln!("[vpn/client] errore: {e}");
        }
    });
}

async fn run_client_tunnel(
    udp: Arc<UdpSocket>,
    exit_addr: SocketAddr,
    my_sk_b64: String,
    exit_pk_b64: String,
    my_vip: Ipv4Addr,
    mut inbound: UnboundedReceiver<(SocketAddr, Vec<u8>)>,
) -> Result<(), String> {
    let my_sk = crypto::sk_from_b64(&my_sk_b64).ok_or("chiave privata non valida")?;
    let exit_pk = crypto::pk_from_b64(&exit_pk_b64).ok_or("chiave pubblica dell'exit non valida")?;
    let sess = new_session(&my_sk, &exit_pk, 1);
    println!("[vpn/client] TUN {my_vip}/24 · uscita CIFRATA (WireGuard) via {exit_addr}");

    let dev = open_tun(my_vip).map_err(|e| e.to_string())?;
    let (mut tun_r, tun_w) = tokio::io::split(dev);
    let tun_w = Arc::new(tokio::sync::Mutex::new(tun_w));

    // Avvia l'handshake e mantieni i timer.
    {
        let sess = sess.clone();
        let udp = udp.clone();
        tokio::spawn(async move {
            loop {
                for dg in wg_tick(&sess).await {
                    let _ = udp.send_to(&encap(&dg), exit_addr).await;
                }
                sleep(Duration::from_millis(250)).await;
            }
        });
    }

    // TUN → cifra → UDP verso l'exit.
    {
        let sess = sess.clone();
        let udp = udp.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let n = match tun_r.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if let Some(dg) = wg_encapsulate(&sess, &buf[..n]).await {
                    let _ = udp.send_to(&encap(&dg), exit_addr).await;
                }
            }
        });
    }

    // UDP (dal demux) → decifra → TUN (e rispedisci le risposte di handshake).
    while let Some((_src, dg)) = inbound.recv().await {
        let (plain, net) = wg_decapsulate(&sess, &dg).await;
        for r in net {
            let _ = udp.send_to(&encap(&r), exit_addr).await;
        }
        if let Some(p) = plain {
            let mut w = tun_w.lock().await;
            let _ = w.write_all(&p).await;
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

fn exit_peer_key(addr: &SocketAddr) -> Option<String> {
    EXIT_PEER_KEYS
        .lock()
        .unwrap()
        .iter()
        .find(|(a, _)| a == addr)
        .map(|(_, k)| k.clone())
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
    mut inbound: UnboundedReceiver<(SocketAddr, Vec<u8>)>,
) -> Result<(), String> {
    let my_sk_b64 = EXIT_MY_SK.lock().unwrap().clone().ok_or("chiave privata mancante")?;
    let my_sk = crypto::sk_from_b64(&my_sk_b64).ok_or("chiave privata non valida")?;
    println!("[vpn/exit] TUN {my_vip}/24 · uscita CIFRATA (WireGuard)");
    let dev = open_tun(my_vip).map_err(|e| e.to_string())?;
    configure_exit_nat();
    let (mut tun_r, tun_w) = tokio::io::split(dev);
    let tun_w = Arc::new(tokio::sync::Mutex::new(tun_w));

    // Sessione per client (per endpoint) e mappa IP virtuale → endpoint client.
    let sessions: Arc<tokio::sync::Mutex<HashMap<SocketAddr, Session>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let routes: Arc<Mutex<HashMap<Ipv4Addr, SocketAddr>>> = Arc::new(Mutex::new(HashMap::new()));

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
                let addr = routes.lock().unwrap().get(&dst).copied();
                let Some(addr) = addr else { continue };
                let sess = sessions.lock().await.get(&addr).cloned();
                if let Some(sess) = sess {
                    if let Some(dg) = wg_encapsulate(&sess, &buf[..n]).await {
                        let _ = udp.send_to(&encap(&dg), addr).await;
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
                let all: Vec<(SocketAddr, Session)> =
                    sessions.lock().await.iter().map(|(a, s)| (*a, s.clone())).collect();
                for (addr, s) in all {
                    for dg in wg_tick(&s).await {
                        let _ = udp.send_to(&encap(&dg), addr).await;
                    }
                }
            }
        });
    }

    let mut index: u32 = 100;
    // UDP (dai client, via demux) → decifra → impara la rotta → TUN → Internet.
    while let Some((src, dg)) = inbound.recv().await {
        let sess = {
            let mut map = sessions.lock().await;
            match map.get(&src) {
                Some(s) => s.clone(),
                None => match exit_peer_key(&src).and_then(|k| crypto::pk_from_b64(&k)) {
                    Some(pk) => {
                        index += 1;
                        let s = new_session(&my_sk, &pk, index);
                        map.insert(src, s.clone());
                        s
                    }
                    None => continue, // chiave pubblica del client sconosciuta
                },
            }
        };
        let (plain, net) = wg_decapsulate(&sess, &dg).await;
        for r in net {
            let _ = udp.send_to(&encap(&r), src).await;
        }
        if let Some(p) = plain {
            if let Some(vip) = ipv4_src(&p) {
                routes.lock().unwrap().insert(vip, src);
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
