//! Protocollo condiviso tra Server e Client.
//!
//! Tutti i messaggi di controllo viaggiano come JSON.
//! - Sul canale **TCP** (segnalazione) usiamo JSON *delimitato da newline*:
//!   ogni messaggio è una riga terminata da `\n`.
//! - Sul canale **UDP** ogni datagramma contiene un singolo messaggio JSON.
//!
//! L'attributo `#[serde(tag = "type")]` fa sì che ogni variante venga
//! serializzata con un campo discriminante `"type"`, ad esempio:
//! `{"type":"Register","auth_key":"ab12..."}`.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Messaggi inviati dal **Client → Server** sul canale TCP di segnalazione.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    /// Autentica la connessione TCP con la chiave persistente del dispositivo
    /// (ottenuta una tantum tramite il login via browser). Il server risolve la
    /// chiave nell'account + dispositivo corrispondente. `wg_public` è la chiave
    /// pubblica WireGuard del dispositivo (presente solo coi client con VPN).
    Register {
        auth_key: String,
        #[serde(default)]
        wg_public: Option<String>,
    },
    /// Il dispositivo sceglie di instradare il proprio traffico attraverso un
    /// exit node (o annulla la scelta con `None`). Il server valida che il
    /// target sia un dispositivo dello stesso account marcato come exit node.
    UseExitNode { exit_device_id: Option<String> },
}

/// Messaggi inviati dal **Server → Client** sul canale TCP di segnalazione.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    /// Conferma di registrazione con l'identità assegnata al dispositivo:
    /// `device_id` e `vip` (IP virtuale IPAM).
    Registered {
        device_id: String,
        #[serde(default)]
        vip: Option<String>,
        info: String,
    },
    /// Registrato ma ancora senza peer online: resta in attesa. In una mesh
    /// arriveranno uno o più `PeerInfo` man mano che gli altri dispositivi
    /// dell'account si collegano.
    Waiting,
    /// Informazioni su un peer della mesh. Può arrivare **più volte** (uno per
    /// ogni altro dispositivo dell'account). Include l'IP virtuale e la chiave
    /// pubblica WireGuard del peer (per il tunnel cifrato).
    PeerInfo {
        peer_id: String,
        peer_name: String,
        peer_addr: SocketAddr,
        is_exit_node: bool,
        #[serde(default)]
        peer_vip: Option<String>,
        #[serde(default)]
        peer_wg_public: Option<String>,
    },
    /// Un peer è andato offline: il client può smettere di considerarlo.
    PeerGone { peer_id: String },
    /// Esito della scelta di un exit node (`UseExitNode`).
    ExitNodeSet {
        exit_device_id: Option<String>,
        ok: bool,
        message: String,
    },
    /// Errore lato server (es. chiave non valida, JSON non valido).
    Error { message: String },
}

/// Messaggi inviati dal **Client → Server** sul canale UDP.
///
/// Serve a comunicare al server l'endpoint UDP *pubblico* del client
/// (l'indirizzo IP + porta così come vengono visti dal server dopo il NAT).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum UdpMessage {
    /// Associa questo endpoint UDP al `device_id` già registrato via TCP.
    UdpRegister { device_id: String },
}

/// # Framing del relay VPN (fallback stile DERP)
///
/// Quando due dispositivi non si raggiungono in diretta (NAT simmetrico, CGNAT,
/// niente port forwarding), i datagrammi WireGuard passano dal **server** che ha
/// un IP pubblico. Viaggiano sulla **stessa porta UDP** dell'apprendimento
/// endpoint (così il mapping NAT è identico a quello del keepalive e funziona
/// ovunque), distinti dal JSON grazie a un byte magico iniziale.
///
/// Formato del frame: `[MAGIC=0x72]['r'][len:u8][device_id][payload…]`
/// - dal **mittente → server** `device_id` è la **destinazione**;
/// - dal **server → destinatario** il server riscrive `device_id` con il
///   **mittente**, così il ricevente sa da chi arriva (serve a indicizzare la
///   sessione WireGuard per identità e non per indirizzo di trasporto).
/// - `payload` è il datagramma WireGuard grezzo (già cifrato).
pub mod relay {
    /// Byte iniziale che marca un frame di relay (fuori dal range del JSON `{`).
    pub const RELAY_MAGIC: u8 = 0x72; // 'r'

    /// `true` se il datagramma è un frame di relay (e non un JSON `UdpMessage`).
    pub fn is_relay(datagram: &[u8]) -> bool {
        datagram.first() == Some(&RELAY_MAGIC)
    }

    /// Costruisce un frame di relay verso/da `peer_id` con il `payload` dato.
    pub fn wrap(peer_id: &str, payload: &[u8]) -> Vec<u8> {
        let id = peer_id.as_bytes();
        let len = id.len().min(255);
        let mut v = Vec::with_capacity(2 + len + payload.len());
        v.push(RELAY_MAGIC);
        v.push(len as u8);
        v.extend_from_slice(&id[..len]);
        v.extend_from_slice(payload);
        v
    }

    /// Estrae `(peer_id, payload)` da un frame di relay, se ben formato.
    pub fn parse(datagram: &[u8]) -> Option<(&str, &[u8])> {
        if datagram.first() != Some(&RELAY_MAGIC) {
            return None;
        }
        let len = *datagram.get(1)? as usize;
        let id_end = 2 + len;
        let id = std::str::from_utf8(datagram.get(2..id_end)?).ok()?;
        let payload = datagram.get(id_end..)?;
        Some((id, payload))
    }

    /// Tabella del relay: mappa bidirezionale `device_id ↔ endpoint UDP pubblico`,
    /// popolata dai keepalive dei client e usata per instradare i frame VPN. È il
    /// cuore del relay stile DERP: dato un frame, sa a chi inoltrarlo e da chi
    /// proviene (per riscrivere l'id in uscita).
    #[derive(Default)]
    pub struct Table {
        by_id: std::collections::HashMap<String, std::net::SocketAddr>,
        by_addr: std::collections::HashMap<std::net::SocketAddr, String>,
    }

    impl Table {
        /// Registra/aggiorna il mapping `id → addr`, ripulendo l'indirizzo
        /// precedente (il NAT del dispositivo può cambiare porta pubblica).
        pub fn upsert(&mut self, id: &str, addr: std::net::SocketAddr) {
            if let Some(old) = self.by_id.insert(id.to_string(), addr) {
                if old != addr {
                    self.by_addr.remove(&old);
                }
            }
            self.by_addr.insert(addr, id.to_string());
        }

        /// Rimuove un dispositivo (alla disconnessione dalla segnalazione).
        pub fn remove(&mut self, id: &str) {
            if let Some(addr) = self.by_id.remove(id) {
                self.by_addr.remove(&addr);
            }
        }

        /// Instrada un frame di relay ricevuto da `src`: se destinazione e
        /// mittente sono noti, restituisce `(bytes_da_inviare, destinazione)` con
        /// l'id riscritto sul **mittente**. `None` se non instradabile.
        pub fn route(
            &self,
            src: std::net::SocketAddr,
            datagram: &[u8],
        ) -> Option<(Vec<u8>, std::net::SocketAddr)> {
            let (dst_id, payload) = parse(datagram)?;
            let dst_addr = *self.by_id.get(dst_id)?;
            let src_id = self.by_addr.get(&src)?;
            Some((wrap(src_id, payload), dst_addr))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn wrap_parse_roundtrip() {
            let wg = [0x01u8, 0x02, 0x03, 0xff, 0x00];
            let frame = wrap("2afdb670deadbeef", &wg);
            assert!(is_relay(&frame));
            let (id, payload) = parse(&frame).expect("frame valido");
            assert_eq!(id, "2afdb670deadbeef");
            assert_eq!(payload, &wg);
        }

        #[test]
        fn json_is_not_relay() {
            // Un `UdpRegister` JSON inizia con '{' (0x7b), non 0x72.
            let json = br#"{"type":"UdpRegister","device_id":"abc"}"#;
            assert!(!is_relay(json));
            assert!(parse(json).is_none());
        }

        #[test]
        fn truncated_frame_is_none() {
            // MAGIC + len che promette 8 byte di id ma il buffer è corto.
            assert!(parse(&[RELAY_MAGIC, 8, b'a', b'b']).is_none());
        }

        #[test]
        fn table_routes_and_rewrites_sender() {
            let a: std::net::SocketAddr = "1.1.1.1:1000".parse().unwrap();
            let b: std::net::SocketAddr = "2.2.2.2:2000".parse().unwrap();
            let mut t = Table::default();
            t.upsert("alice", a);
            t.upsert("bob", b);

            // Alice manda un frame destinato a "bob".
            let frame = wrap("bob", b"ciphertext");
            let (out, dst) = t.route(a, &frame).expect("instradabile");
            assert_eq!(dst, b, "va all'endpoint di bob");
            // In uscita l'id è riscritto sul mittente (alice) col payload intatto.
            assert_eq!(parse(&out), Some(("alice", &b"ciphertext"[..])));
        }

        #[test]
        fn table_unknown_destination_is_dropped() {
            let a: std::net::SocketAddr = "1.1.1.1:1000".parse().unwrap();
            let mut t = Table::default();
            t.upsert("alice", a);
            // Destinatario sconosciuto → nessun inoltro.
            assert!(t.route(a, &wrap("nessuno", b"x")).is_none());
            // Mittente sconosciuto (non registrato) → nessun inoltro.
            let unknown: std::net::SocketAddr = "9.9.9.9:9".parse().unwrap();
            t.upsert("bob", "2.2.2.2:2".parse().unwrap());
            assert!(t.route(unknown, &wrap("bob", b"x")).is_none());
        }

        #[test]
        fn table_remove_and_nat_rebind() {
            let a1: std::net::SocketAddr = "1.1.1.1:1000".parse().unwrap();
            let a2: std::net::SocketAddr = "1.1.1.1:2000".parse().unwrap();
            let b: std::net::SocketAddr = "2.2.2.2:2000".parse().unwrap();
            let mut t = Table::default();
            t.upsert("alice", a1);
            t.upsert("bob", b);
            // Il NAT di alice cambia porta pubblica: il vecchio indirizzo non deve
            // più risolvere a "alice".
            t.upsert("alice", a2);
            assert!(t.route(a1, &wrap("bob", b"x")).is_none(), "vecchio addr disattivato");
            assert!(t.route(a2, &wrap("bob", b"x")).is_some(), "nuovo addr attivo");
            // Rimozione: alice sparisce del tutto.
            t.remove("alice");
            assert!(t.route(a2, &wrap("bob", b"x")).is_none());
        }
    }
}
