//! Backoffice web del control plane (axum).
//!
//! Espone:
//! - **registrazione / login / logout** con sessione via cookie;
//! - **elenco dispositivi** dell'account con stato online e azione "collega";
//! - **device-code flow**: le API che il client usa per farsi autorizzare
//!   aprendo il browser (`/api/device/start`, `/auth/device`, `/api/device/poll`).
//!
//! Lo stato *live* (dispositivi collegati in questo momento, con il loro canale
//! TCP e l'endpoint UDP pubblico) è condiviso con la segnalazione nel binario
//! `server`, così il pulsante "collega" del backoffice può inviare `PeerInfo`
//! ai due dispositivi scelti.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::{mpsc, Mutex};

use crate::db;
use crate::proto::ServerMessage;

const SESSION_TTL: i64 = 7 * 24 * 3600; // 7 giorni

/// Un dispositivo attualmente collegato via TCP di segnalazione.
pub struct LiveDevice {
    pub user_id: i64,
    pub name: String,
    /// Canale verso il task di scrittura TCP di quel dispositivo.
    pub tx: mpsc::UnboundedSender<ServerMessage>,
    /// Endpoint UDP pubblico, noto dopo il primo datagramma UDP del client.
    pub udp_addr: Option<SocketAddr>,
    /// Copia in cache del flag exit node (sorgente di verità nel DB).
    pub is_exit_node: bool,
    /// device_id dell'exit node attualmente scelto da questo dispositivo (se
    /// sta instradando il traffico attraverso un altro nodo).
    pub using_exit: Option<String>,
    /// IP virtuale (IPAM) assegnato al dispositivo.
    pub vip: Option<String>,
    /// Chiave pubblica WireGuard del dispositivo (per il tunnel cifrato).
    pub wg_public: Option<String>,
}

/// Mappa `device_id → LiveDevice` dei dispositivi online in questo momento.
pub type Live = Arc<Mutex<HashMap<String, LiveDevice>>>;

/// Stato condiviso passato ad axum.
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Mutex<Connection>>,
    pub live: Live,
    /// URL pubblico del backoffice (per costruire i link del device-code flow).
    pub public_url: String,
}

/// Costruisce il router del backoffice.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/register", get(register_page).post(register_submit))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", post(logout))
        .route("/devices", get(devices_page))
        .route("/devices/exit-node", post(exit_node_submit))
        .route("/devices/remesh", post(remesh_submit))
        .route("/auth/device", get(auth_device_page))
        .route("/auth/device/approve", post(auth_device_approve))
        .route("/api/device/start", post(api_device_start))
        .route("/api/device/poll", get(api_device_poll))
        .with_state(state)
}

// -------------------------------------------------------------------- mesh ---

/// Annuncia `subject_id` a tutti gli altri dispositivi online dell'account e
/// viceversa: ogni coppia riceve l'endpoint dell'altro → parte l'hole punching.
/// È così che si forma la **mesh completa** (tutti-con-tutti).
pub async fn mesh_announce(live: &Live, user_id: i64, subject_id: &str) {
    let guard = live.lock().await;
    let subject = match guard.get(subject_id) {
        Some(d) if d.user_id == user_id => d,
        _ => return,
    };
    let Some(subj_addr) = subject.udp_addr else { return };
    let subj_name = subject.name.clone();
    let subj_exit = subject.is_exit_node;
    let subj_vip = subject.vip.clone();
    let subj_wg = subject.wg_public.clone();
    let subj_tx = subject.tx.clone();

    for (id, d) in guard.iter() {
        if id == subject_id || d.user_id != user_id {
            continue;
        }
        let Some(other_addr) = d.udp_addr else { continue };
        // Al subject: ecco il peer `d`.
        let _ = subj_tx.send(ServerMessage::PeerInfo {
            peer_id: id.clone(),
            peer_name: d.name.clone(),
            peer_addr: other_addr,
            is_exit_node: d.is_exit_node,
            peer_vip: d.vip.clone(),
            peer_wg_public: d.wg_public.clone(),
        });
        // Al peer `d`: ecco il subject.
        let _ = d.tx.send(ServerMessage::PeerInfo {
            peer_id: subject_id.to_string(),
            peer_name: subj_name.clone(),
            peer_addr: subj_addr,
            is_exit_node: subj_exit,
            peer_vip: subj_vip.clone(),
            peer_wg_public: subj_wg.clone(),
        });
    }
}

/// Ri-annuncia l'intera mesh dell'account (tutti verso tutti).
pub async fn mesh_announce_all(live: &Live, user_id: i64) {
    let ids: Vec<String> = {
        let guard = live.lock().await;
        guard
            .iter()
            .filter(|(_, d)| d.user_id == user_id && d.udp_addr.is_some())
            .map(|(id, _)| id.clone())
            .collect()
    };
    for id in ids {
        mesh_announce(live, user_id, &id).await;
    }
}

/// Comunica agli altri dispositivi dell'account che `device_id` è andato offline.
pub async fn peer_gone(live: &Live, user_id: i64, device_id: &str) {
    let guard = live.lock().await;
    for (id, d) in guard.iter() {
        if id == device_id || d.user_id != user_id {
            continue;
        }
        let _ = d.tx.send(ServerMessage::PeerGone {
            peer_id: device_id.to_string(),
        });
    }
}

// ----------------------------------------------------------------- helper ---

/// Legge un cookie dagli header della richiesta.
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix(&format!("{name}=")) {
            return Some(v.to_string());
        }
    }
    None
}

/// Utente autenticato (id, email) a partire dal cookie di sessione.
async fn current_user(state: &AppState, headers: &HeaderMap) -> Option<(i64, String)> {
    let token = cookie(headers, "session")?;
    let conn = state.db.lock().await;
    db::session_user(&conn, &token).ok().flatten()
}

fn session_cookie(token: &str) -> String {
    format!("session={token}; HttpOnly; Path=/; SameSite=Lax; Max-Age={SESSION_TTL}")
}

fn clear_cookie() -> String {
    "session=; HttpOnly; Path=/; Max-Age=0".to_string()
}

/// Redirect 303 che imposta anche un cookie.
fn redirect_cookie(location: &str, cookie: &str) -> Response {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, location)
        .header(header::SET_COOKIE, cookie)
        .body(axum::body::Body::empty())
        .unwrap()
}

/// Escape minimale per inserire testo utente nell'HTML.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Layout comune di pagina.
fn layout(title: &str, user: Option<&str>, body: &str) -> Html<String> {
    let nav = match user {
        Some(email) => format!(
            r#"<span class="who">{}</span>
               <form method="post" action="/logout" style="display:inline">
                 <button class="link">esci</button>
               </form>"#,
            esc(email)
        ),
        None => r#"<a href="/login">accedi</a> · <a href="/register">registrati</a>"#.to_string(),
    };
    Html(format!(
        r#"<!doctype html><html lang="it"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · p2p control plane</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; }}
  header {{ display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #8884; padding-bottom:.6rem; margin-bottom:1.4rem; }}
  header .brand {{ font-weight:700; }}
  h1 {{ font-size:1.4rem; }}
  input, select {{ padding:.5rem; font-size:1rem; width:100%; box-sizing:border-box; margin:.25rem 0 .8rem; }}
  button {{ padding:.55rem 1rem; font-size:1rem; cursor:pointer; border-radius:.4rem; border:1px solid #8886; background:#4f8cff; color:#fff; }}
  button.link {{ background:none; border:none; color:#4f8cff; padding:0; }}
  table {{ width:100%; border-collapse:collapse; margin:1rem 0; }}
  th,td {{ text-align:left; padding:.5rem; border-bottom:1px solid #8883; }}
  .badge {{ font-size:.8rem; padding:.1rem .5rem; border-radius:1rem; }}
  .on {{ background:#1c7c3033; color:#1c7c30; }}
  .off {{ background:#8883; color:#888; }}
  .msg {{ background:#4f8cff22; padding:.6rem .8rem; border-radius:.4rem; margin-bottom:1rem; }}
  .err {{ background:#e5484d22; color:#e5484d; padding:.6rem .8rem; border-radius:.4rem; margin-bottom:1rem; }}
  code {{ background:#8882; padding:.1rem .3rem; border-radius:.2rem; }}
  a {{ color:#4f8cff; }}
</style></head><body>
<header><span class="brand">🔗 p2p control plane</span><nav>{nav}</nav></header>
{body}
</body></html>"#
    ))
}

// ------------------------------------------------------------------ pagine ---

async fn index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if current_user(&state, &headers).await.is_some() {
        Redirect::to("/devices").into_response()
    } else {
        Redirect::to("/login").into_response()
    }
}

#[derive(Deserialize)]
struct AuthForm {
    email: String,
    password: String,
    #[serde(default)]
    next: String,
}

#[derive(Deserialize)]
struct FlashQuery {
    #[serde(default)]
    err: Option<String>,
    #[serde(default)]
    next: Option<String>,
}

async fn register_page(Query(q): Query<FlashQuery>) -> Response {
    let err = q
        .err
        .map(|e| format!(r#"<div class="err">{}</div>"#, esc(&e)))
        .unwrap_or_default();
    let body = format!(
        r#"<h1>Registrati</h1>{err}
        <form method="post" action="/register">
          <label>Email<input name="email" type="email" required></label>
          <label>Password<input name="password" type="password" minlength="8" required></label>
          <button type="submit">Crea account</button>
        </form>
        <p>Hai già un account? <a href="/login">Accedi</a>.</p>"#
    );
    layout("Registrati", None, &body).into_response()
}

async fn register_submit(State(state): State<AppState>, Form(f): Form<AuthForm>) -> Response {
    if f.password.len() < 8 {
        return Redirect::to("/register?err=La+password+deve+avere+almeno+8+caratteri").into_response();
    }
    let conn = state.db.lock().await;
    match db::create_user(&conn, f.email.trim(), &f.password) {
        Ok(user_id) => match db::create_session(&conn, user_id, SESSION_TTL) {
            Ok(token) => redirect_cookie("/devices", &session_cookie(&token)),
            Err(e) => Redirect::to(&format!("/register?err={}", urlenc(&e.to_string()))).into_response(),
        },
        Err(e) => Redirect::to(&format!("/register?err={}", urlenc(&e))).into_response(),
    }
}

async fn login_page(Query(q): Query<FlashQuery>) -> Response {
    let err = q
        .err
        .map(|e| format!(r#"<div class="err">{}</div>"#, esc(&e)))
        .unwrap_or_default();
    let next = esc(q.next.as_deref().unwrap_or(""));
    let body = format!(
        r#"<h1>Accedi</h1>{err}
        <form method="post" action="/login">
          <input type="hidden" name="next" value="{next}">
          <label>Email<input name="email" type="email" required></label>
          <label>Password<input name="password" type="password" required></label>
          <button type="submit">Accedi</button>
        </form>
        <p>Non hai un account? <a href="/register">Registrati</a>.</p>"#
    );
    layout("Accedi", None, &body).into_response()
}

async fn login_submit(State(state): State<AppState>, Form(f): Form<AuthForm>) -> Response {
    let dest = if f.next.starts_with('/') { f.next.clone() } else { "/devices".to_string() };
    let conn = state.db.lock().await;
    match db::verify_login(&conn, f.email.trim(), &f.password) {
        Ok(Some(user_id)) => match db::create_session(&conn, user_id, SESSION_TTL) {
            Ok(token) => redirect_cookie(&dest, &session_cookie(&token)),
            Err(_) => Redirect::to("/login?err=Errore+interno").into_response(),
        },
        Ok(None) => {
            let q = format!("/login?err=Credenziali+non+valide&next={}", urlenc(&f.next));
            Redirect::to(&q).into_response()
        }
        Err(_) => Redirect::to("/login?err=Errore+interno").into_response(),
    }
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(token) = cookie(&headers, "session") {
        let conn = state.db.lock().await;
        let _ = db::delete_session(&conn, &token);
    }
    redirect_cookie("/login", &clear_cookie())
}

#[derive(Deserialize)]
struct DevicesQuery {
    #[serde(default)]
    msg: Option<String>,
    #[serde(default)]
    err: Option<String>,
}

async fn devices_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<DevicesQuery>,
) -> Response {
    let Some((user_id, email)) = current_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };

    let devices = {
        let conn = state.db.lock().await;
        db::devices_for_user(&conn, user_id).unwrap_or_default()
    };

    // Stato live: quali device sono online e con endpoint UDP noto.
    let live = state.live.lock().await;
    let mut rows = String::new();
    let mut ready_count = 0;
    for d in &devices {
        let (online, addr) = match live.get(&d.id) {
            Some(l) if l.user_id == user_id => {
                if l.udp_addr.is_some() {
                    ready_count += 1;
                }
                (
                    true,
                    l.udp_addr.map(|a| a.to_string()).unwrap_or_else(|| "in attesa UDP".into()),
                )
            }
            _ => (false, "—".into()),
        };
        let status = if online {
            r#"<span class="badge on">online</span>"#
        } else {
            r#"<span class="badge off">offline</span>"#
        };
        // Toggle di disponibilità come exit node.
        let (exit_label, exit_next, exit_badge) = if d.is_exit_node {
            ("Disattiva exit", "false", r#" <span class="badge on">exit node</span>"#)
        } else {
            ("Rendi exit node", "true", "")
        };
        rows.push_str(&format!(
            r#"<tr>
                 <td>{name}{exit_badge}</td>
                 <td>{status}</td>
                 <td><code>{addr}</code></td>
                 <td>
                   <form method="post" action="/devices/exit-node" style="display:inline">
                     <input type="hidden" name="device_id" value="{id}">
                     <input type="hidden" name="enabled" value="{exit_next}">
                     <button class="link">{exit_label}</button>
                   </form>
                 </td>
               </tr>"#,
            name = esc(&d.name),
            exit_badge = exit_badge,
            status = status,
            addr = esc(&addr),
            id = esc(&d.id),
            exit_next = exit_next,
            exit_label = exit_label,
        ));
    }
    drop(live);

    if rows.is_empty() {
        rows = r#"<tr><td colspan="4">Nessun dispositivo. Avvia il client e approva il login.</td></tr>"#.to_string();
    }

    let mesh_note = format!(
        r#"<p>I dispositivi online vengono collegati automaticamente <strong>tutti-con-tutti</strong> (mesh) via hole punching, non appena pubblicano il loro endpoint. Online e pronti adesso: <strong>{ready_count}</strong>.</p>
        <form method="post" action="/devices/remesh" style="display:inline">
          <button type="submit">Ricollega tutti</button>
        </form>"#
    );

    let flash = q
        .msg
        .map(|m| format!(r#"<div class="msg">{}</div>"#, esc(&m)))
        .or_else(|| q.err.map(|e| format!(r#"<div class="err">{}</div>"#, esc(&e))))
        .unwrap_or_default();

    let body = format!(
        r#"<h1>I tuoi dispositivi</h1>{flash}
        <table>
          <thead><tr><th>Nome</th><th>Stato</th><th>Endpoint UDP</th><th>Exit node</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
        {mesh_note}
        <p style="margin-top:2rem;color:#888">Per aggiungere un dispositivo: esegui il client, si aprirà il browser per approvare il login. Il flag <strong>exit node</strong> marca un dispositivo come disponibile a fare da uscita; quale usare lo sceglierai dal client.</p>"#
    );
    layout("Dispositivi", Some(&email), &body).into_response()
}

#[derive(Deserialize)]
struct ExitNodeForm {
    device_id: String,
    enabled: String, // "true" / "false"
}

/// Marca/smarca un dispositivo come disponibile a fare da exit node.
async fn exit_node_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<ExitNodeForm>,
) -> Response {
    let Some((user_id, _)) = current_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let enabled = f.enabled == "true";
    let updated = {
        let conn = state.db.lock().await;
        db::set_exit_node(&conn, user_id, &f.device_id, enabled).unwrap_or(false)
    };
    if updated {
        // Aggiorna la cache live e ri-annuncia, così i peer apprendono subito la
        // nuova disponibilità come exit node.
        {
            let mut guard = state.live.lock().await;
            if let Some(d) = guard.get_mut(&f.device_id) {
                if d.user_id == user_id {
                    d.is_exit_node = enabled;
                }
            }
        }
        mesh_announce(&state.live, user_id, &f.device_id).await;
    }
    Redirect::to("/devices?msg=Exit+node+aggiornato").into_response()
}

/// Ri-annuncia l'intera mesh dell'account (utile dopo cambi di rete).
async fn remesh_submit(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some((user_id, _)) = current_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    mesh_announce_all(&state.live, user_id).await;
    Redirect::to("/devices?msg=Mesh+ricollegata").into_response()
}

// ----------------------------------------------------- device-code flow ---

#[derive(Deserialize)]
struct CodeQuery {
    code: String,
}

async fn auth_device_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<CodeQuery>,
) -> Response {
    // Serve essere loggati: altrimenti login e poi ritorno qui.
    let Some((_, email)) = current_user(&state, &headers).await else {
        let next = urlenc(&format!("/auth/device?code={}", q.code));
        return Redirect::to(&format!("/login?next={next}")).into_response();
    };

    let da = {
        let conn = state.db.lock().await;
        db::get_device_auth(&conn, &q.code).ok().flatten()
    };
    let body = match da {
        None => r#"<h1>Richiesta non valida</h1><p>Codice di autorizzazione sconosciuto o scaduto.</p>"#.to_string(),
        Some(da) if da.approved => format!(
            r#"<h1>Dispositivo già autorizzato</h1><p>«{}» è collegato al tuo account. Puoi tornare al client.</p><p><a href="/devices">Vai ai dispositivi</a></p>"#,
            esc(&da.name)
        ),
        Some(da) => format!(
            r#"<h1>Autorizza dispositivo</h1>
            <p>Il dispositivo <strong>«{}»</strong> chiede di collegarsi al tuo account.</p>
            <form method="post" action="/auth/device/approve">
              <input type="hidden" name="code" value="{}">
              <button type="submit">Approva e collega</button>
            </form>"#,
            esc(&da.name),
            esc(&q.code)
        ),
    };
    layout("Autorizza dispositivo", Some(&email), &body).into_response()
}

#[derive(Deserialize)]
struct ApproveForm {
    code: String,
}

async fn auth_device_approve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<ApproveForm>,
) -> Response {
    let Some((user_id, email)) = current_user(&state, &headers).await else {
        let next = urlenc(&format!("/auth/device?code={}", f.code));
        return Redirect::to(&format!("/login?next={next}")).into_response();
    };
    let result = {
        let conn = state.db.lock().await;
        db::approve_device_auth(&conn, &f.code, user_id)
    };
    let body = match result {
        Ok(Some(_)) => r#"<h1>✅ Dispositivo autorizzato</h1><p>Torna al client: completerà il collegamento automaticamente.</p><p><a href="/devices">Vai ai dispositivi</a></p>"#.to_string(),
        _ => r#"<h1>Errore</h1><p>Impossibile autorizzare il dispositivo (codice non valido?).</p>"#.to_string(),
    };
    layout("Dispositivo autorizzato", Some(&email), &body).into_response()
}

#[derive(Deserialize)]
struct StartReq {
    name: String,
}

/// Il client avvia il login: crea una richiesta pendente e ritorna il link
/// da aprire nel browser + il `code` per il polling.
async fn api_device_start(State(state): State<AppState>, Json(req): Json<StartReq>) -> Response {
    let name = if req.name.trim().is_empty() { "dispositivo" } else { req.name.trim() };
    let conn = state.db.lock().await;
    match db::create_device_auth(&conn, name) {
        Ok(code) => {
            let url = format!("{}/auth/device?code={}", state.public_url, code);
            Json(json!({ "code": code, "verification_url": url })).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response(),
    }
}

/// Il client interroga finché l'utente non approva dal browser.
async fn api_device_poll(State(state): State<AppState>, Query(q): Query<CodeQuery>) -> Response {
    let da = {
        let conn = state.db.lock().await;
        db::get_device_auth(&conn, &q.code).ok().flatten()
    };
    match da {
        None => (StatusCode::NOT_FOUND, Json(json!({ "error": "unknown_code" }))).into_response(),
        Some(da) if da.approved => Json(json!({
            "approved": true,
            "device_id": da.device_id,
            "auth_key": da.auth_key,
            "name": da.name,
            "vip": da.vip,
        }))
        .into_response(),
        Some(_) => Json(json!({ "approved": false })).into_response(),
    }
}

/// Percent-encoding minimale per i valori messi in querystring.
fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
