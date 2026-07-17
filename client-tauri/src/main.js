// Frontend del client Tauri. Tutta la rete (TCP/UDP/hole punching) è nel core
// Rust (src-tauri/src/lib.rs), esposto come comandi `invoke` + eventi.

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);
const logEl = $("log");

function log(line) {
  logEl.textContent += "\n" + line;
  logEl.scrollTop = logEl.scrollHeight;
}

function setStatus(state) {
  const map = {
    idle: "non connesso",
    connecting: "connessione…",
    registered: "registrato",
    punching: "hole punching…",
    connected: "✅ connesso",
    error: "errore",
  };
  const badge = $("status");
  badge.textContent = map[state] || state;
  badge.className = "badge " + state;
}

function show(view) {
  $("view-login").classList.toggle("hidden", view !== "login");
  $("view-main").classList.toggle("hidden", view !== "main");
}

// Eventi emessi dal core Rust durante la segnalazione / hole punching.
listen("log", (e) => log(e.payload));
listen("status", (e) => setStatus(e.payload));

// Elenco exit node disponibili → popola il selettore.
listen("exit_nodes", (e) => {
  const names = e.payload || [];
  const sel = $("exit-select");
  const current = sel.value;
  sel.innerHTML = '<option value="">Nessuno — traffico diretto</option>';
  for (const n of names) {
    const o = document.createElement("option");
    o.value = n;
    o.textContent = n;
    sel.appendChild(o);
  }
  sel.value = current;
  if (names.length) $("exit-box").classList.remove("hidden");
});

$("btn-exit").addEventListener("click", async () => {
  const name = $("exit-select").value;
  try {
    await invoke("use_exit", { name });
    log(name ? `Exit node richiesto: ${name}` : "Traffico diretto (nessun exit node)");
  } catch (err) {
    log("Errore exit node: " + err);
  }
});

// Login: avvia il device-code flow, mostra il link, attende l'approvazione.
$("btn-login").addEventListener("click", async () => {
  const name = $("name").value.trim() || "dispositivo";
  $("btn-login").disabled = true;
  try {
    const start = await invoke("login_start", { name });
    $("login-url").textContent = start.url;
    $("login-progress").classList.remove("hidden");
    log("In attesa di approvazione dal browser…");
    const devName = await invoke("login_wait", { code: start.code });
    log("Dispositivo autorizzato: " + devName);
    enterMain(devName);
  } catch (err) {
    log("Errore login: " + err);
    $("btn-login").disabled = false;
  }
});

$("btn-connect").addEventListener("click", async () => {
  $("btn-connect").disabled = true;
  setStatus("connecting");
  try {
    await invoke("connect");
  } catch (err) {
    log("Errore: " + err);
    setStatus("error");
    $("btn-connect").disabled = false;
  }
});

$("btn-logout").addEventListener("click", async () => {
  await invoke("logout");
  show("login");
  $("btn-login").disabled = false;
  $("login-progress").classList.add("hidden");
  logEl.textContent = "Dispositivo rimosso.";
});

function enterMain(name) {
  $("dev-name").textContent = name;
  setStatus("idle");
  show("main");
}

// All'avvio: decidi quale schermata mostrare in base alla config salvata.
(async () => {
  try {
    const state = await invoke("get_state");
    if (state.logged_in) {
      enterMain(state.name);
      logEl.textContent = "Pronto. Premi Connetti.";
    } else {
      show("login");
      logEl.textContent = "Esegui l'accesso per collegare questo dispositivo.";
    }
  } catch (err) {
    logEl.textContent = "Errore init: " + err;
  }
})();
