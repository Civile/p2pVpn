//! Libreria condivisa del control plane P2P.
//!
//! Moduli:
//! - [`proto`]  — messaggi di controllo (TCP di segnalazione + UDP) in JSON.
//! - [`db`]     — storage SQLite: utenti, dispositivi, sessioni, device-auth.
//! - [`web`]    — backoffice web (axum): login/registrazione, elenco device,
//!               approvazione del login del client (device-code flow).

pub mod proto;

// Moduli del control plane: presenti solo con la feature `server`.
#[cfg(feature = "server")]
pub mod db;
#[cfg(feature = "server")]
pub mod web;

// Data plane VPN (exit node): presente solo con la feature `vpn`.
#[cfg(feature = "vpn")]
pub mod vpn;

// Routing automatico full-tunnel (client VPN): presente solo con la feature `vpn`.
#[cfg(feature = "vpn")]
pub mod route;

// Re-export del protocollo per compatibilità: `p2p_holepunch::ClientMessage`, ecc.
pub use proto::{ClientMessage, ServerMessage, UdpMessage};
