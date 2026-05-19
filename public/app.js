// --- Elements ---
const statusBar = document.getElementById("statusBar");
const statusDot = document.getElementById("statusDot");
const statusText = document.getElementById("statusText");
const configDbStatus = document.getElementById("configDbStatus");
const schemaStatus = document.getElementById("schemaStatus");
const databaseCount = document.getElementById("databaseCount");
const profileCountEl = document.getElementById("profileCount");
const databasePills = document.getElementById("databasePills");
const adminSecret = document.getElementById("adminSecret");
const adminStatusBadge = document.getElementById("adminStatusBadge");
const adminHint = document.getElementById("adminHint");
const databaseForm = document.getElementById("databaseForm");
const databaseResult = document.getElementById("databaseResult");
const databaseTable = document.getElementById("databaseTable");
const refreshDatabasesButton = document.getElementById("refreshDatabasesButton");
const testDatabaseButton = document.getElementById("testDatabaseButton");
const clearDatabaseButton = document.getElementById("clearDatabaseButton");
const tokenDbName = document.getElementById("tokenDbName");
const sqlDbName = document.getElementById("sqlDbName");
const tokenForm = document.getElementById("tokenForm");
const sqlForm = document.getElementById("sqlForm");
const tokenOutput = document.getElementById("tokenOutput");
const sqlToken = document.getElementById("sqlToken");
const sqlResult = document.getElementById("sqlResult");
const logsOutput = document.getElementById("logsOutput");
const logLimit = document.getElementById("logLimit");
const refreshAllButton = document.getElementById("refreshAllButton");
const refreshLogsButton = document.getElementById("refreshLogsButton");
const tokenProfileName = document.getElementById("tokenProfileName");
const profileForm = document.getElementById("profileForm");
const profileResult = document.getElementById("profileResult");
const profileDbName = document.getElementById("profileDbName");
const profileGenDbName = document.getElementById("profileGenDbName");
const profileGenerateForm = document.getElementById("profileGenerateForm");
const profileGenResult = document.getElementById("profileGenResult");
const applyGeneratedProfile = document.getElementById("applyGeneratedProfile");
const introspectTablesButton = document.getElementById("introspectTablesButton");
const clearProfileButton = document.getElementById("clearProfileButton");
const refreshProfilesButton = document.getElementById("refreshProfilesButton");
const profileTable = document.getElementById("profileTable");

let managedDatabases = [];
let lastGeneratedProfile = null;
const ADMIN_SECRET_STORAGE_KEY = "pg-proxy-admin-secret";

// --- Panel Toggle ---
document.querySelectorAll(".panel-toggle").forEach((btn) => {
  btn.addEventListener("click", (e) => {
    e.preventDefault();
    const targetId = btn.dataset.target;
    const body = document.getElementById(targetId);
    if (!body) return;
    const expanded = btn.getAttribute("aria-expanded") === "true";
    btn.setAttribute("aria-expanded", String(!expanded));
    body.classList.toggle("collapsed", expanded);
  });
});

// --- Helpers ---
function getAdminSecretValue() { return adminSecret.value.trim(); }

function getAdminHeaders() {
  return { "Content-Type": "application/json", "x-admin-secret": getAdminSecretValue() };
}

function updateAdminUi() {
  if (getAdminSecretValue()) {
    adminStatusBadge.textContent = "Ready";
    adminStatusBadge.className = "badge ok";
    adminHint.textContent = "Admin secret set.";
  } else {
    adminStatusBadge.textContent = "Locked";
    adminStatusBadge.className = "badge";
    adminHint.textContent = "Required for all management actions.";
  }
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json();
  if (!response.ok) {
    if (response.status === 401) throw new Error("Unauthorized. Check admin secret.");
    throw new Error(data.error || "Request failed");
  }
  return data;
}

function escapeHtml(v) {
  return String(v).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
function escapeAttr(v) { return escapeHtml(v).replace(/"/g,"&quot;"); }

// --- Health ---
async function loadHealth() {
  try {
    const data = await requestJson("/api/health");
    statusDot.className = data.ok ? "status-dot ok" : "status-dot bad";
    statusText.textContent = data.ok ? "Config DB healthy • Schema initialized" : "Config DB error";

    if (data.config_db && data.config_db.status === "healthy") {
      configDbStatus.textContent = "Healthy ✓";
      configDbStatus.style.color = "var(--accent)";
    } else {
      configDbStatus.textContent = data.config_db ? data.config_db.error : "Error";
      configDbStatus.style.color = "var(--danger)";
    }

    schemaStatus.textContent = data.schema_initialized ? "OK ✓" : "Missing";
    schemaStatus.style.color = data.schema_initialized ? "var(--accent)" : "var(--danger)";
    databaseCount.textContent = String(data.database_count || 0);
    profileCountEl.textContent = String(data.profile_count || 0);
  } catch (err) {
    statusDot.className = "status-dot bad";
    statusText.textContent = "Connection failed";
    configDbStatus.textContent = "Error";
    configDbStatus.style.color = "var(--danger)";
  }
}

// --- Databases ---
function renderDatabaseSelectors(databases) {
  databaseCount.textContent = String(databases.length);
  databasePills.innerHTML = "";
  tokenDbName.innerHTML = "";
  sqlDbName.innerHTML = "";

  for (const db of databases) {
    const name = typeof db === "string" ? db : db.db_name;
    databasePills.innerHTML += `<span class="pill">${escapeHtml(name)}</span>`;
    tokenDbName.innerHTML += `<option value="${escapeAttr(name)}">${escapeHtml(name)}</option>`;
    sqlDbName.innerHTML += `<option value="${escapeAttr(name)}">${escapeHtml(name)}</option>`;
  }
  if (databases.length === 0) {
    databasePills.innerHTML = '<span class="pill">None</span>';
  }
}

function renderManagedDatabases() {
  if (managedDatabases.length === 0) {
    databaseTable.className = "list-empty";
    databaseTable.textContent = "No databases yet.";
    return;
  }
  databaseTable.className = "";
  databaseTable.innerHTML = managedDatabases.map((db) => `
    <div class="list-item">
      <strong>${escapeHtml(db.db_name)}</strong>
      <code>${escapeHtml(db.connection_string)}</code>
      <div class="list-meta">
        <span>${new Date(db.updated_at).toLocaleDateString()}</span>
        <div class="btn-row">
          <button class="btn btn-ghost btn-sm" data-action="edit" data-db-name="${escapeAttr(db.db_name)}">Edit</button>
          <button class="btn btn-ghost btn-sm" data-action="delete" data-db-name="${escapeAttr(db.db_name)}">Del</button>
        </div>
      </div>
    </div>
  `).join("");
}

async function loadManagedDatabases() {
  if (!getAdminSecretValue()) {
    managedDatabases = [];
    renderManagedDatabases();
    renderDatabaseSelectors([]);
    return;
  }
  try {
    const data = await requestJson("/api/managed-databases", {
      headers: { "x-admin-secret": getAdminSecretValue() },
    });
    managedDatabases = data.databases || [];
    renderManagedDatabases();
    renderDatabaseSelectors(managedDatabases);
    renderProfileSelectors(managedDatabases);
    await loadProfiles();
  } catch (err) {
    databaseResult.value = err.message;
  }
}

// --- Logs ---
async function loadLogs() {
  const limit = Number(logLimit.value || 50);
  try {
    const data = await requestJson(`/api/logs?limit=${encodeURIComponent(limit)}`);
    logsOutput.value = JSON.stringify(data.logs, null, 2);
  } catch (err) {
    logsOutput.value = err.message;
  }
}

// --- Database Form ---
databaseForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = {
    db_name: databaseForm.elements.db_name.value.trim(),
    connection_string: databaseForm.elements.connection_string.value.trim(),
  };
  try {
    const data = await requestJson("/api/managed-databases", {
      method: "POST", headers: getAdminHeaders(), body: JSON.stringify(body),
    });
    databaseResult.value = JSON.stringify(data, null, 2);
    await loadManagedDatabases();
    await loadHealth();
  } catch (err) { databaseResult.value = err.message; }
});

testDatabaseButton.addEventListener("click", async () => {
  const body = { connection_string: databaseForm.elements.connection_string.value.trim() };
  try {
    const data = await requestJson("/api/managed-databases/test", {
      method: "POST", headers: getAdminHeaders(), body: JSON.stringify(body),
    });
    databaseResult.value = JSON.stringify(data, null, 2);
  } catch (err) { databaseResult.value = err.message; }
});

clearDatabaseButton.addEventListener("click", () => { databaseForm.reset(); databaseResult.value = ""; });

databaseTable.addEventListener("click", async (e) => {
  const target = e.target.closest("[data-action]");
  if (!target) return;
  const action = target.dataset.action;
  const dbName = target.dataset.dbName;
  const db = managedDatabases.find((d) => d.db_name === dbName);

  if (action === "edit" && db) {
    databaseForm.elements.db_name.value = db.db_name;
    databaseForm.elements.connection_string.value = db.connection_string;
    databaseResult.value = `Loaded ${db.db_name}`;
    return;
  }
  if (action === "delete") {
    try {
      await requestJson(`/api/managed-databases/${encodeURIComponent(dbName)}`, {
        method: "DELETE", headers: { "x-admin-secret": getAdminSecretValue() },
      });
      databaseResult.value = `Deleted ${dbName}`;
      await loadManagedDatabases();
      await loadHealth();
    } catch (err) { databaseResult.value = err.message; }
  }
});

// --- Token ---
tokenForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(tokenForm);
  const body = { db_name: fd.get("db_name"), access: fd.get("access") };
  const ttl = fd.get("ttl_seconds");
  if (ttl) body.ttl_seconds = Number(ttl);
  const profile = fd.get("profile_name");
  if (profile) body.profile_name = profile;

  try {
    const data = await requestJson("/api/token", {
      method: "POST", headers: getAdminHeaders(), body: JSON.stringify(body),
    });
    tokenOutput.value = data.aiConnectionPacket || JSON.stringify(data, null, 2);
    sqlToken.value = data.token;
    sqlDbName.value = data.db_name;
  } catch (err) { tokenOutput.value = err.message; }
});

// --- SQL ---
sqlForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(sqlForm);
  let params = [];
  try { params = JSON.parse(fd.get("params") || "[]"); } catch (err) { sqlResult.value = err.message; return; }

  try {
    const data = await requestJson("/api/sql", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${fd.get("token")}` },
      body: JSON.stringify({ db_name: fd.get("db_name"), sql: fd.get("sql"), params }),
    });
    sqlResult.value = JSON.stringify(data, null, 2);
  } catch (err) { sqlResult.value = err.message; }
});
