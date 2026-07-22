// Frontend del client Tauri. Il core Rust (src-tauri/src/lib.rs) pilota
// l'eseguibile CLI: login, elenco exit node, accensione/spegnimento del tunnel.

const { invoke } = window.__TAURI__.core;

const $ = (id) => document.getElementById(id);
const logEl = $("log");

function setLog(text) {
  logEl.textContent = text && text.length ? text : "—";
  logEl.scrollTop = logEl.scrollHeight;
}

function setBadge(state, text) {
  const b = $("status");
  b.className = "badge " + state;
  b.textContent = text;
}

function show(view) {
  $("view-login").classList.toggle("hidden", view !== "login");
  $("view-main").classList.toggle("hidden", view !== "main");
}

// ----- Login (device-code flow) -----
$("btn-login").addEventListener("click", async () => {
  const name = $("name").value.trim() || "dispositivo";
  $("btn-login").disabled = true;
  try {
    const start = await invoke("login_start", { name });
    $("login-url").textContent = start.url;
    $("login-progress").classList.remove("hidden");
    const devName = await invoke("login_wait", { code: start.code });
    enterMain(devName);
  } catch (err) {
    setLog("Errore login: " + err);
    $("btn-login").disabled = false;
  }
});

$("btn-logout").addEventListener("click", async () => {
  try { await invoke("vpn_stop"); } catch (e) {}
  await invoke("logout");
  stopPolling();
  show("login");
  $("btn-login").disabled = false;
  $("login-progress").classList.add("hidden");
  setLog("Dispositivo rimosso.");
});

// ----- Exit node -----
async function refreshExits() {
  const sel = $("exit-select");
  const btn = $("btn-refresh");
  btn.disabled = true;
  const prev = sel.value;
  try {
    const names = await invoke("vpn_list_exits");
    sel.innerHTML = "";
    if (!names.length) {
      sel.innerHTML = '<option value="">Nessun exit node online</option>';
    } else {
      for (const n of names) {
        const o = document.createElement("option");
        o.value = n; o.textContent = n;
        sel.appendChild(o);
      }
      if (names.includes(prev)) sel.value = prev;
    }
  } catch (err) {
    setLog("Errore elenco exit node: " + err);
  } finally {
    btn.disabled = false;
  }
}
$("btn-refresh").addEventListener("click", refreshExits);

// ----- Interruttore VPN -----
let vpnOn = false;
$("btn-vpn").addEventListener("click", async () => {
  const btn = $("btn-vpn");
  btn.disabled = true;
  try {
    if (vpnOn) {
      setBadge("connecting", "spegnimento…");
      await invoke("vpn_stop");
    } else {
      const name = $("exit-select").value;
      if (!name) { setLog("Scegli prima un exit node."); btn.disabled = false; return; }
      setBadge("connecting", "connessione…");
      setLog("Avvio VPN verso " + name + " — inserisci la password se richiesta…");
      await invoke("vpn_start", { name });
    }
  } catch (err) {
    setLog("" + err);
    setBadge("error", "errore");
  } finally {
    btn.disabled = false;
    poll();
  }
});

// ----- Polling dello stato -----
let pollTimer = null;
function startPolling() { if (!pollTimer) pollTimer = setInterval(poll, 2000); }
function stopPolling() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }

async function poll() {
  let st;
  try { st = await invoke("vpn_status"); } catch (e) { return; }
  vpnOn = st.running;
  const btn = $("btn-vpn");
  const sel = $("exit-select");
  // Verde SOLO quando il routing è stato davvero applicato (non basta l'handshake).
  const routed = /\[route\] ✅ VPN attiva/i.test(st.log);
  const handshaking = /handshake OK|handshake WireGuard avviato/i.test(st.log);
  if (st.running) {
    if (routed) setBadge("on", "✅ VPN attiva");
    else setBadge("connecting", handshaking ? "handshake…" : "connessione…");
    btn.textContent = "Disattiva VPN";
    btn.classList.add("danger");
    sel.disabled = true;
    $("btn-refresh").disabled = true;
    $("hint").textContent = routed
      ? "Tutto il traffico esce dall'exit node. Premi Disattiva per spegnere."
      : "Handshake in corso…";
  } else {
    setBadge("off", "VPN spenta");
    btn.textContent = "Attiva VPN";
    btn.classList.remove("danger");
    sel.disabled = false;
    $("btn-refresh").disabled = false;
    $("hint").textContent = "Scegli un exit node e premi Attiva. Verrà chiesta la password (serve per instradare il traffico).";
  }
  if (st.log) setLog(st.log);
}

function enterMain(name) {
  $("dev-name").textContent = name;
  setBadge("off", "VPN spenta");
  show("main");
  setLog("Pronto. Aggiorno gli exit node…");
  refreshExits();
  poll();
  startPolling();
}

// All'avvio: login o schermata principale.
(async () => {
  try {
    const state = await invoke("get_state");
    if (state.logged_in) {
      enterMain(state.name);
    } else {
      show("login");
      setLog("Esegui l'accesso per collegare questo dispositivo.");
    }
  } catch (err) {
    setLog("Errore init: " + err);
  }
})();
