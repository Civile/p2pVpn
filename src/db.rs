//! Storage SQLite del control plane.
//!
//! Contiene lo schema (utenti, dispositivi, sessioni, device-auth) e le query
//! di supporto. Il tutto è sincrono (rusqlite): il chiamante serializza gli
//! accessi con un `Mutex` (vedi `web::AppState`). Le operazioni sono brevi.

use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand_core::{OsRng, RngCore};
use rusqlite::{Connection, OptionalExtension};

/// Riga della tabella `devices`.
#[derive(Debug, Clone)]
pub struct Device {
    pub id: String,
    pub user_id: i64,
    pub name: String,
    pub auth_key: String,
    pub last_seen: Option<i64>,
    /// `true` se il dispositivo è marcato come disponibile a fare da exit node.
    pub is_exit_node: bool,
    /// IP virtuale assegnato dal control plane (IPAM), es. `10.7.0.2`.
    pub vip: Option<String>,
    /// Chiave pubblica WireGuard (base64), pubblicata dal client al Register.
    pub wg_public: Option<String>,
}

/// Secondi trascorsi dall'epoch Unix (orologio di sistema).
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Genera una stringa esadecimale casuale di `n` byte (2·n caratteri).
pub fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    let mut s = String::with_capacity(n * 2);
    for b in buf {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Apre (o crea) il database e applica lo schema.
pub fn open(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY,
            email         TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at    INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS devices (
            id           TEXT PRIMARY KEY,
            user_id      INTEGER NOT NULL REFERENCES users(id),
            name         TEXT NOT NULL,
            auth_key     TEXT UNIQUE NOT NULL,
            created_at   INTEGER NOT NULL,
            last_seen    INTEGER,
            is_exit_node INTEGER NOT NULL DEFAULT 0,
            vip          TEXT,
            wg_public    TEXT
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT PRIMARY KEY,
            user_id    INTEGER NOT NULL REFERENCES users(id),
            expires_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS device_auth (
            code       TEXT PRIMARY KEY,
            name       TEXT NOT NULL,
            approved   INTEGER NOT NULL DEFAULT 0,
            user_id    INTEGER,
            device_id  TEXT,
            auth_key   TEXT,
            vip        TEXT,
            created_at INTEGER NOT NULL
        );
        "#,
    )?;

    // Migrazioni per DB creati prima di queste colonne (errore ignorato se già
    // presenti).
    for stmt in [
        "ALTER TABLE devices ADD COLUMN is_exit_node INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE devices ADD COLUMN vip TEXT",
        "ALTER TABLE devices ADD COLUMN wg_public TEXT",
        "ALTER TABLE device_auth ADD COLUMN vip TEXT",
    ] {
        let _ = conn.execute(stmt, []);
    }
    Ok(conn)
}

// ------------------------------------------------------------------ utenti ---

/// Crea un utente con password hashata (argon2). Ritorna l'id del nuovo utente.
pub fn create_user(conn: &Connection, email: &str, password: &str) -> Result<i64, String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("hashing password: {e}"))?
        .to_string();
    conn.execute(
        "INSERT INTO users (email, password_hash, created_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![email, hash, now()],
    )
    .map_err(|e| match e {
        rusqlite::Error::SqliteFailure(_, _) => "Email già registrata.".to_string(),
        other => format!("db: {other}"),
    })?;
    Ok(conn.last_insert_rowid())
}

/// Verifica email + password. Ritorna l'id utente se le credenziali sono valide.
pub fn verify_login(conn: &Connection, email: &str, password: &str) -> rusqlite::Result<Option<i64>> {
    let row: Option<(i64, String)> = conn
        .query_row(
            "SELECT id, password_hash FROM users WHERE email = ?1",
            [email],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((id, hash)) = row else {
        return Ok(None);
    };
    let ok = PasswordHash::new(&hash)
        .ok()
        .map(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
        .unwrap_or(false);
    Ok(ok.then_some(id))
}

/// Email di un utente dato il suo id.
pub fn user_email(conn: &Connection, user_id: i64) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT email FROM users WHERE id = ?1", [user_id], |r| r.get(0))
        .optional()
}

// -------------------------------------------------------------- sessioni ---

/// Crea una sessione (cookie) valida `ttl_secs` secondi. Ritorna il token.
pub fn create_session(conn: &Connection, user_id: i64, ttl_secs: i64) -> rusqlite::Result<String> {
    let token = random_hex(32);
    conn.execute(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![token, user_id, now() + ttl_secs],
    )?;
    Ok(token)
}

/// Risolve un token di sessione nell'utente (id, email), se ancora valido.
pub fn session_user(conn: &Connection, token: &str) -> rusqlite::Result<Option<(i64, String)>> {
    conn.query_row(
        "SELECT u.id, u.email FROM sessions s \
         JOIN users u ON u.id = s.user_id \
         WHERE s.token = ?1 AND s.expires_at > ?2",
        rusqlite::params![token, now()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()
}

/// Elimina una sessione (logout).
pub fn delete_session(conn: &Connection, token: &str) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM sessions WHERE token = ?1", [token])?;
    Ok(())
}

// -------------------------------------------------------------- device ---

/// Elenca i dispositivi di un utente (ordine di creazione).
pub fn devices_for_user(conn: &Connection, user_id: i64) -> rusqlite::Result<Vec<Device>> {
    let mut stmt = conn.prepare(
        "SELECT id, user_id, name, auth_key, last_seen, is_exit_node, vip, wg_public \
         FROM devices WHERE user_id = ?1 ORDER BY created_at ASC",
    )?;
    let rows = stmt.query_map([user_id], row_to_device)?;
    rows.collect()
}

/// Mappa una riga (con le 8 colonne canoniche) in un `Device`.
fn row_to_device(r: &rusqlite::Row) -> rusqlite::Result<Device> {
    Ok(Device {
        id: r.get(0)?,
        user_id: r.get(1)?,
        name: r.get(2)?,
        auth_key: r.get(3)?,
        last_seen: r.get(4)?,
        is_exit_node: r.get::<_, i64>(5)? != 0,
        vip: r.get(6)?,
        wg_public: r.get(7)?,
    })
}

/// Prossimo IP virtuale libero (`10.7.0.2 ..= 10.7.0.254`) per l'account.
pub fn next_free_vip(conn: &Connection, user_id: i64) -> rusqlite::Result<String> {
    let mut stmt = conn.prepare("SELECT vip FROM devices WHERE user_id = ?1 AND vip IS NOT NULL")?;
    let used: std::collections::HashSet<String> = stmt
        .query_map([user_id], |r| r.get::<_, String>(0))?
        .filter_map(Result::ok)
        .collect();
    for host in 2u8..=254 {
        let candidate = format!("10.7.0.{host}");
        if !used.contains(&candidate) {
            return Ok(candidate);
        }
    }
    // Subnet esaurita: fallback (documentato come limite).
    Ok("10.7.0.254".to_string())
}

/// Registra la chiave pubblica WireGuard di un dispositivo (al Register).
pub fn set_wg_public(conn: &Connection, device_id: &str, wg_public: &str) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE devices SET wg_public = ?1 WHERE id = ?2",
        rusqlite::params![wg_public, device_id],
    )?;
    Ok(())
}

/// Imposta/rimuove la disponibilità come exit node per un dispositivo
/// dell'utente. Ritorna `true` se un dispositivo è stato aggiornato.
pub fn set_exit_node(
    conn: &Connection,
    user_id: i64,
    device_id: &str,
    enabled: bool,
) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "UPDATE devices SET is_exit_node = ?1 WHERE id = ?2 AND user_id = ?3",
        rusqlite::params![enabled as i64, device_id, user_id],
    )?;
    Ok(n > 0)
}

/// Risolve una `auth_key` nel dispositivo corrispondente (usato dalla
/// segnalazione TCP per autenticare il client).
pub fn device_by_auth_key(conn: &Connection, auth_key: &str) -> rusqlite::Result<Option<Device>> {
    conn.query_row(
        "SELECT id, user_id, name, auth_key, last_seen, is_exit_node, vip, wg_public \
         FROM devices WHERE auth_key = ?1",
        [auth_key],
        row_to_device,
    )
    .optional()
}

/// Aggiorna il timestamp `last_seen` di un dispositivo (quando si collega).
pub fn touch_device(conn: &Connection, device_id: &str) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE devices SET last_seen = ?1 WHERE id = ?2",
        rusqlite::params![now(), device_id],
    )?;
    Ok(())
}

// --------------------------------------------------------- device-auth ---

/// Stato di una richiesta di device-auth (device-code flow).
#[derive(Debug, Clone)]
pub struct DeviceAuth {
    pub code: String,
    pub name: String,
    pub approved: bool,
    pub device_id: Option<String>,
    pub auth_key: Option<String>,
    pub vip: Option<String>,
}

/// Il client avvia il login: crea una richiesta pendente e ritorna il `code`.
pub fn create_device_auth(conn: &Connection, name: &str) -> rusqlite::Result<String> {
    let code = random_hex(24);
    conn.execute(
        "INSERT INTO device_auth (code, name, created_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![code, name, now()],
    )?;
    Ok(code)
}

/// Legge lo stato di una richiesta di device-auth.
pub fn get_device_auth(conn: &Connection, code: &str) -> rusqlite::Result<Option<DeviceAuth>> {
    conn.query_row(
        "SELECT code, name, approved, device_id, auth_key, vip FROM device_auth WHERE code = ?1",
        [code],
        |r| {
            Ok(DeviceAuth {
                code: r.get(0)?,
                name: r.get(1)?,
                approved: r.get::<_, i64>(2)? != 0,
                device_id: r.get(3)?,
                auth_key: r.get(4)?,
                vip: r.get(5)?,
            })
        },
    )
    .optional()
}

/// L'utente approva dal browser: crea il dispositivo, lega la richiesta e
/// ritorna `(device_id, auth_key)` che il client recupererà col polling.
pub fn approve_device_auth(
    conn: &Connection,
    code: &str,
    user_id: i64,
) -> rusqlite::Result<Option<(String, String)>> {
    let Some(da) = get_device_auth(conn, code)? else {
        return Ok(None);
    };
    if da.approved {
        // Già approvata: ritorna le credenziali esistenti (idempotente).
        return Ok(da.device_id.zip(da.auth_key));
    }
    let device_id = random_hex(16);
    let auth_key = random_hex(32);
    let vip = next_free_vip(conn, user_id)?; // IPAM: IP virtuale stabile
    conn.execute(
        "INSERT INTO devices (id, user_id, name, auth_key, created_at, vip) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![device_id, user_id, da.name, auth_key, now(), vip],
    )?;
    conn.execute(
        "UPDATE device_auth SET approved = 1, user_id = ?1, device_id = ?2, auth_key = ?3, vip = ?4 WHERE code = ?5",
        rusqlite::params![user_id, device_id, auth_key, vip, code],
    )?;
    Ok(Some((device_id, auth_key)))
}
