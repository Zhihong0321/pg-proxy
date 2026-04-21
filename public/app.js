const healthValue = document.getElementById("healthValue");
const healthBadge = document.getElementById("healthBadge");
const databaseCount = document.getElementById("databaseCount");
const databasePills = document.getElementById("databasePills");
const adminSecret = document.getElementById("adminSecret");
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

let managedDatabases = [];

function getAdminHeaders() {
  return {
    "Content-Type": "application/json",
    "x-admin-secret": adminSecret.value.trim(),
  };
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || "Request failed");
  }

  return data;
}

function renderDatabaseSelectors(databases) {
  databaseCount.textContent = String(databases.length);
  databasePills.innerHTML = "";
  tokenDbName.innerHTML = "";
  sqlDbName.innerHTML = "";

  if (databases.length === 0) {
    const pill = document.createElement("span");
    pill.className = "pill empty";
    pill.textContent = "No target databases saved";
    databasePills.appendChild(pill);
    return;
  }

  for (const database of databases) {
    const dbName = typeof database === "string" ? database : database.db_name;

    const pill = document.createElement("span");
    pill.className = "pill";
    pill.textContent = dbName;
    databasePills.appendChild(pill);

    const tokenOption = document.createElement("option");
    tokenOption.value = dbName;
    tokenOption.textContent = dbName;
    tokenDbName.appendChild(tokenOption);

    const sqlOption = document.createElement("option");
    sqlOption.value = dbName;
    sqlOption.textContent = dbName;
    sqlDbName.appendChild(sqlOption);
  }
}

function renderManagedDatabases() {
  if (managedDatabases.length === 0) {
    databaseTable.className = "database-table empty";
    databaseTable.textContent = "No saved databases yet.";
    return;
  }

  databaseTable.className = "database-table";
  const rows = managedDatabases
    .map(
      (database) => `
        <div class="database-row">
          <div class="database-main">
            <strong>${escapeHtml(database.db_name)}</strong>
            <code>${escapeHtml(database.connection_string)}</code>
          </div>
          <div class="database-meta">
            <span>Updated ${new Date(database.updated_at).toLocaleString()}</span>
            <div class="button-row">
              <button class="button ghost small" type="button" data-action="edit" data-db-name="${escapeAttribute(database.db_name)}">Edit</button>
              <button class="button ghost small" type="button" data-action="delete" data-db-name="${escapeAttribute(database.db_name)}">Delete</button>
            </div>
          </div>
        </div>
      `
    )
    .join("");

  databaseTable.innerHTML = rows;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function escapeAttribute(value) {
  return escapeHtml(value).replace(/"/g, "&quot;");
}

function fillDatabaseForm(database) {
  databaseForm.elements.db_name.value = database.db_name;
  databaseForm.elements.connection_string.value = database.connection_string;
  databaseResult.value = `Loaded ${database.db_name} into form.`;
}

function clearDatabaseForm() {
  databaseForm.reset();
  databaseResult.value = "";
}

async function loadHealth() {
  const data = await requestJson("/api/health");
  healthValue.textContent = data.ok ? "OK" : "DOWN";
  healthBadge.textContent = data.ok ? "Healthy" : "Down";
  healthBadge.className = data.ok ? "badge ok" : "badge bad";
}

async function loadManagedDatabases() {
  if (!adminSecret.value.trim()) {
    managedDatabases = [];
    renderManagedDatabases();
    renderDatabaseSelectors([]);
    databaseResult.value = "Enter admin secret to manage target databases.";
    return;
  }

  const data = await requestJson("/api/managed-databases", {
    headers: {
      "x-admin-secret": adminSecret.value.trim(),
    },
  });

  managedDatabases = data.databases || [];
  renderManagedDatabases();
  renderDatabaseSelectors(managedDatabases);
  await loadHealth();
}

async function loadLogs() {
  const limit = Number(logLimit.value || 50);
  const data = await requestJson(`/api/logs?limit=${encodeURIComponent(limit)}`);
  logsOutput.value = JSON.stringify(data.logs, null, 2);
}

databaseForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const body = {
    db_name: databaseForm.elements.db_name.value.trim(),
    connection_string: databaseForm.elements.connection_string.value.trim(),
  };

  try {
    const data = await requestJson("/api/managed-databases", {
      method: "POST",
      headers: getAdminHeaders(),
      body: JSON.stringify(body),
    });

    databaseResult.value = JSON.stringify(data, null, 2);
    await loadManagedDatabases();
    await loadLogs();
  } catch (error) {
    databaseResult.value = error.message;
  }
});

testDatabaseButton.addEventListener("click", async () => {
  const body = {
    connection_string: databaseForm.elements.connection_string.value.trim(),
  };

  try {
    const data = await requestJson("/api/managed-databases/test", {
      method: "POST",
      headers: getAdminHeaders(),
      body: JSON.stringify(body),
    });

    databaseResult.value = JSON.stringify(data, null, 2);
  } catch (error) {
    databaseResult.value = error.message;
  }
});

clearDatabaseButton.addEventListener("click", () => {
  clearDatabaseForm();
});

databaseTable.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) {
    return;
  }

  const action = target.dataset.action;
  const dbName = target.dataset.dbName;

  if (!action || !dbName) {
    return;
  }

  const database = managedDatabases.find((item) => item.db_name === dbName);

  if (action === "edit" && database) {
    fillDatabaseForm(database);
    return;
  }

  if (action === "delete") {
    try {
      const data = await requestJson(`/api/managed-databases/${encodeURIComponent(dbName)}`, {
        method: "DELETE",
        headers: {
          "x-admin-secret": adminSecret.value.trim(),
        },
      });

      databaseResult.value = JSON.stringify(data, null, 2);
      await loadManagedDatabases();
      await loadLogs();
    } catch (error) {
      databaseResult.value = error.message;
    }
  }
});

tokenForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const formData = new FormData(tokenForm);
  const body = {
    db_name: formData.get("db_name"),
    access: formData.get("access"),
    ttl_seconds: Number(formData.get("ttl_seconds") || 3600),
  };

  try {
    const data = await requestJson("/api/token", {
      method: "POST",
      headers: getAdminHeaders(),
      body: JSON.stringify(body),
    });

    tokenOutput.value = JSON.stringify(data, null, 2);
    sqlToken.value = data.token;
    sqlDbName.value = data.db_name;
    await loadLogs();
  } catch (error) {
    tokenOutput.value = error.message;
  }
});

sqlForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const formData = new FormData(sqlForm);
  let params = [];

  try {
    params = JSON.parse(formData.get("params") || "[]");
    if (!Array.isArray(params)) {
      throw new Error("Params must be a JSON array");
    }
  } catch (error) {
    sqlResult.value = error.message;
    return;
  }

  try {
    const data = await requestJson("/api/sql", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${formData.get("token")}`,
      },
      body: JSON.stringify({
        db_name: formData.get("db_name"),
        sql: formData.get("sql"),
        params,
      }),
    });

    sqlResult.value = JSON.stringify(data, null, 2);
    await loadLogs();
  } catch (error) {
    sqlResult.value = error.message;
  }
});

refreshAllButton.addEventListener("click", async () => {
  await loadHealth();
  await loadManagedDatabases();
  await loadLogs();
});

refreshDatabasesButton.addEventListener("click", loadManagedDatabases);
refreshLogsButton.addEventListener("click", loadLogs);
adminSecret.addEventListener("change", loadManagedDatabases);
adminSecret.addEventListener("blur", loadManagedDatabases);

Promise.all([loadHealth(), loadLogs()]).catch((error) => {
  healthValue.textContent = "ERROR";
  healthBadge.textContent = "Error";
  healthBadge.className = "badge bad";
  databaseResult.value = error.message;
});
