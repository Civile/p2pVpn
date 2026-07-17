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
