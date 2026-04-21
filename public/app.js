const healthValue = document.getElementById("healthValue");
const healthBadge = document.getElementById("healthBadge");
const databaseCount = document.getElementById("databaseCount");
const databasePills = document.getElementById("databasePills");
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

async function requestJson(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || "Request failed");
  }

  return data;
}

function setDatabases(databases) {
  databaseCount.textContent = String(databases.length);
  databasePills.innerHTML = "";
  tokenDbName.innerHTML = "";
  sqlDbName.innerHTML = "";

  for (const dbName of databases) {
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

async function loadHealth() {
  const data = await requestJson("/api/health");
  healthValue.textContent = data.ok ? "OK" : "DOWN";
  healthBadge.textContent = data.ok ? "Healthy" : "Down";
  healthBadge.className = data.ok ? "badge ok" : "badge bad";
  setDatabases(data.databases || []);
}

async function loadLogs() {
  const limit = Number(logLimit.value || 50);
  const data = await requestJson(`/api/logs?limit=${encodeURIComponent(limit)}`);
  logsOutput.value = JSON.stringify(data.logs, null, 2);
}

tokenForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const formData = new FormData(tokenForm);
  const adminSecret = formData.get("adminSecret");
  const body = {
    db_name: formData.get("db_name"),
    access: formData.get("access"),
    ttl_seconds: Number(formData.get("ttl_seconds") || 3600),
  };

  try {
    const data = await requestJson("/api/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-admin-secret": adminSecret,
      },
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
  await loadLogs();
});

refreshLogsButton.addEventListener("click", loadLogs);

Promise.all([loadHealth(), loadLogs()]).catch((error) => {
  healthValue.textContent = "ERROR";
  healthBadge.textContent = "Error";
  healthBadge.className = "badge bad";
  tokenOutput.value = error.message;
});
