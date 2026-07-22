//! # Routing automatico "full tunnel" (feature `vpn`)
//!
//! Trasforma il tunnel cifrato client→exit in una **VPN reale**: instrada tutto
//! il traffico del sistema dentro l'interfaccia TUN, così esce dall'exit node.
//!
//! È la parte che, in `EXIT-NODE.md`, era **manuale** (passo 6) e pericolosa: se
//! mandi il default nel tunnel senza tenere raggiungibile l'exit, ti tagli fuori
//! dalla rete. Qui è automatizzata e **reversibile**:
//!
//! 1. salva lo stato attuale (gateway di default, interfaccia WAN, DNS);
//! 2. **pinna** l'IP pubblico dell'exit al gateway attuale (rotta host), così i
//!    pacchetti WireGuard verso l'exit NON entrano nel tunnel (niente loop);
//! 3. instrada `0.0.0.0/1` + `128.0.0.0/1` dentro il TUN (coprono l'intero
//!    default senza sovrascrivere la rotta di default originale);
//! 4. imposta un DNS pubblico (1.1.1.1) per non dipendere da resolver in LAN;
//! 5. **ripristina** tutto su `restore()` (chiamata da Ctrl-C o a fine sessione).
//!
//! Il chiamante applica il full tunnel **solo dopo** che l'handshake WireGuard è
//! confermato (primo datagramma di risposta dall'exit): se il tunnel non si
//! stabilisce, non tocchiamo il routing e la rete resta intatta.
//!
//! Supporta **macOS** (`route`/`networksetup`) e **Linux** (`ip`/`resolv.conf`).

use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::Mutex;

/// DNS pubblici usati mentre il full tunnel è attivo.
const PUBLIC_DNS: [&str; 2] = ["1.1.1.1", "8.8.8.8"];

/// Stato salvato per poter ripristinare il routing originale.
struct Saved {
    exit_ip: Ipv4Addr,
    gateway: String,
    tun_if: String,
    dns: Option<DnsBackup>,
}

/// Backup del DNS, dipendente dall'OS.
#[cfg(target_os = "macos")]
struct DnsBackup {
    /// Nome del network service (es. "Wi-Fi") su cui abbiamo cambiato il DNS.
    service: String,
    /// Server DNS precedenti (vuoto = "Empty", cioè DHCP).
    previous: Vec<String>,
}
#[cfg(target_os = "linux")]
struct DnsBackup {
    /// Contenuto originale di `/etc/resolv.conf`.
    previous: String,
}

static SAVED: Mutex<Option<Saved>> = Mutex::new(None);

/// Esegue un comando, logga l'esito, ritorna `true` se è andato a buon fine.
fn run(cmd: &str, args: &[&str]) -> bool {
    let ok = Command::new(cmd)
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    println!("[route] {} {} → {}", cmd, args.join(" "), if ok { "ok" } else { "FALLITO" });
    ok
}

/// Cattura l'output di un comando (stdout) come stringa.
fn capture(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        None
    }
}

/// Applica il full tunnel: instrada tutto il traffico dentro il TUN `tun_if`
/// (trovato dal suo IP virtuale `my_vip`), tenendo l'exit raggiungibile.
/// Idempotente: se un full tunnel è già attivo non fa nulla.
pub fn apply_full_tunnel(exit_ip: Ipv4Addr, my_vip: Ipv4Addr) -> Result<(), String> {
    if SAVED.lock().unwrap().is_some() {
        return Ok(()); // già attivo
    }
    let gateway = default_gateway().ok_or("gateway di default non trovato")?;
    let tun_if = tun_interface_for(my_vip)
        .ok_or_else(|| format!("interfaccia TUN con IP {my_vip} non trovata"))?;
    println!("[route] full tunnel: gw={gateway} tun={tun_if} exit={exit_ip}");

    // 1) Tieni l'exit raggiungibile per la sua strada normale (fuori dal tunnel).
    pin_exit(exit_ip, &gateway);
    // 2) Manda tutto il resto dentro il tunnel (0/1 + 128/1 = default "coprente").
    default_via_tun(&tun_if);
    // 3) DNS pubblico (best effort: non blocca in caso di errore).
    let dns = set_public_dns();

    *SAVED.lock().unwrap() = Some(Saved { exit_ip, gateway, tun_if, dns });
    println!("[route] ✅ VPN attiva: tutto il traffico esce dall'exit node.");
    Ok(())
}

/// Ripristina il routing/DNS originali. Idempotente e sicuro da chiamare più
/// volte (es. da Ctrl-C e di nuovo alla chiusura).
pub fn restore() {
    let saved = SAVED.lock().unwrap().take();
    let Some(s) = saved else { return };
    println!("[route] ripristino del routing originale…");
    unset_default_via_tun(&s.tun_if);
    unpin_exit(s.exit_ip, &s.gateway);
    if let Some(dns) = s.dns {
        restore_dns(dns);
    }
    println!("[route] ripristino completato.");
}

// ============================================================================
//  macOS
// ============================================================================
#[cfg(target_os = "macos")]
fn default_gateway() -> Option<String> {
    // `route -n get default` stampa "    gateway: 192.168.1.1".
    let out = capture("route", &["-n", "get", "default"])?;
    out.lines()
        .find_map(|l| l.trim().strip_prefix("gateway:").map(|g| g.trim().to_string()))
}

#[cfg(target_os = "macos")]
fn tun_interface_for(vip: Ipv4Addr) -> Option<String> {
    // Scansiona `ifconfig`: l'interfaccia è l'ultimo header "utunN:" visto prima
    // della riga "inet <vip>".
    let out = capture("ifconfig", &[])?;
    let mut current = String::new();
    for line in out.lines() {
        if !line.starts_with(char::is_whitespace) {
            if let Some((name, _)) = line.split_once(':') {
                current = name.to_string();
            }
        } else if line.trim_start().starts_with(&format!("inet {vip} ")) {
            return Some(current.clone());
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn pin_exit(exit_ip: Ipv4Addr, gateway: &str) {
    // Rimuove un'eventuale gemella e ripinna (idempotente).
    let ip = exit_ip.to_string();
    let _ = Command::new("route").args(["-n", "delete", "-host", &ip]).status();
    run("route", &["-n", "add", "-host", &ip, gateway]);
}

#[cfg(target_os = "macos")]
fn unpin_exit(exit_ip: Ipv4Addr, _gateway: &str) {
    run("route", &["-n", "delete", "-host", &exit_ip.to_string()]);
}

#[cfg(target_os = "macos")]
fn default_via_tun(tun_if: &str) {
    run("route", &["-n", "add", "-net", "0.0.0.0/1", "-interface", tun_if]);
    run("route", &["-n", "add", "-net", "128.0.0.0/1", "-interface", tun_if]);
}

#[cfg(target_os = "macos")]
fn unset_default_via_tun(_tun_if: &str) {
    run("route", &["-n", "delete", "-net", "0.0.0.0/1"]);
    run("route", &["-n", "delete", "-net", "128.0.0.0/1"]);
}

#[cfg(target_os = "macos")]
fn set_public_dns() -> Option<DnsBackup> {
    // Trova il network service attivo (quello con l'interfaccia del default gw).
    let service = primary_network_service()?;
    let previous = capture("networksetup", &["-getdnsservers", &service])
        .map(|s| {
            s.lines()
                .map(|l| l.trim().to_string())
                .filter(|l| l.parse::<Ipv4Addr>().is_ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut args = vec!["-setdnsservers", &service];
    args.extend(PUBLIC_DNS.iter());
    run("networksetup", &args);
    Some(DnsBackup { service, previous })
}

#[cfg(target_os = "macos")]
fn restore_dns(b: DnsBackup) {
    if b.previous.is_empty() {
        // Nessun DNS statico prima: torna a DHCP ("Empty").
        run("networksetup", &["-setdnsservers", &b.service, "Empty"]);
    } else {
        let mut args = vec!["-setdnsservers", b.service.as_str()];
        args.extend(b.previous.iter().map(|s| s.as_str()));
        run("networksetup", &args);
    }
}

/// Mappa l'interfaccia del default gateway (es. `en0`) al nome del network
/// service (es. `Wi-Fi`), leggendo `networksetup -listnetworkserviceorder`.
#[cfg(target_os = "macos")]
fn primary_network_service() -> Option<String> {
    let dev = default_interface()?;
    let out = capture("networksetup", &["-listnetworkserviceorder"])?;
    // Blocchi tipo:
    //   (1) Wi-Fi
    //   (Hardware Port: Wi-Fi, Device: en0)
    let mut last_name: Option<String> = None;
    for line in out.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix('(') {
            if let Some(idx) = rest.find(')') {
                // "(1) Wi-Fi" → nome dopo ") "
                if let Some(name) = t.splitn(2, ") ").nth(1) {
                    last_name = Some(name.trim().to_string());
                }
                let _ = idx;
            }
        }
        if t.contains(&format!("Device: {dev})")) {
            if let Some(n) = &last_name {
                return Some(n.clone());
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn default_interface() -> Option<String> {
    let out = capture("route", &["-n", "get", "default"])?;
    out.lines()
        .find_map(|l| l.trim().strip_prefix("interface:").map(|g| g.trim().to_string()))
}

// ============================================================================
//  Linux
// ============================================================================
#[cfg(target_os = "linux")]
fn default_gateway() -> Option<String> {
    // `ip route show default` → "default via 192.168.1.1 dev eth0 ...".
    let out = capture("ip", &["route", "show", "default"])?;
    let mut it = out.split_whitespace();
    while let Some(tok) = it.next() {
        if tok == "via" {
            return it.next().map(|s| s.to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn tun_interface_for(vip: Ipv4Addr) -> Option<String> {
    // `ip -o -4 addr show` → "3: tun0    inet 10.7.0.2/24 ...".
    let out = capture("ip", &["-o", "-4", "addr", "show"])?;
    let needle = format!("inet {vip}/");
    for line in out.lines() {
        if line.contains(&needle) {
            return line.split_whitespace().nth(1).map(|s| s.to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn pin_exit(exit_ip: Ipv4Addr, gateway: &str) {
    let cidr = format!("{exit_ip}/32");
    let _ = Command::new("ip").args(["route", "del", &cidr]).status();
    run("ip", &["route", "add", &cidr, "via", gateway]);
}

#[cfg(target_os = "linux")]
fn unpin_exit(exit_ip: Ipv4Addr, _gateway: &str) {
    run("ip", &["route", "del", &format!("{exit_ip}/32")]);
}

#[cfg(target_os = "linux")]
fn default_via_tun(tun_if: &str) {
    run("ip", &["route", "add", "0.0.0.0/1", "dev", tun_if]);
    run("ip", &["route", "add", "128.0.0.0/1", "dev", tun_if]);
}

#[cfg(target_os = "linux")]
fn unset_default_via_tun(tun_if: &str) {
    run("ip", &["route", "del", "0.0.0.0/1", "dev", tun_if]);
    run("ip", &["route", "del", "128.0.0.0/1", "dev", tun_if]);
}

#[cfg(target_os = "linux")]
fn set_public_dns() -> Option<DnsBackup> {
    let previous = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let new = PUBLIC_DNS.iter().map(|d| format!("nameserver {d}\n")).collect::<String>();
    match std::fs::write("/etc/resolv.conf", new) {
        Ok(_) => {
            println!("[route] /etc/resolv.conf → DNS pubblico");
            Some(DnsBackup { previous })
        }
        Err(e) => {
            eprintln!("[route] impossibile scrivere /etc/resolv.conf: {e}");
            None
        }
    }
}

#[cfg(target_os = "linux")]
fn restore_dns(b: DnsBackup) {
    if let Err(e) = std::fs::write("/etc/resolv.conf", b.previous) {
        eprintln!("[route] ripristino /etc/resolv.conf fallito: {e}");
    } else {
        println!("[route] /etc/resolv.conf ripristinato");
    }
}

// ============================================================================
//  Altri OS (Windows, ecc.): non supportato, no-op con avviso.
// ============================================================================
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn default_gateway() -> Option<String> {
    None
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn tun_interface_for(_vip: Ipv4Addr) -> Option<String> {
    None
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn pin_exit(_exit_ip: Ipv4Addr, _gateway: &str) {}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn unpin_exit(_exit_ip: Ipv4Addr, _gateway: &str) {}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn default_via_tun(_tun_if: &str) {}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn unset_default_via_tun(_tun_if: &str) {}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
struct DnsBackup;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn set_public_dns() -> Option<DnsBackup> {
    None
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn restore_dns(_b: DnsBackup) {}
