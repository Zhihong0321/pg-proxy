require("dotenv").config();

const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const path = require("path");
const { URL } = require("url");
const { Pool } = require("pg");

const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL;
const PROXY_ADMIN_SECRET = process.env.PROXY_ADMIN_SECRET;
const PROXY_SIGNING_SECRET = process.env.PROXY_SIGNING_SECRET;
const PUBLIC_DIR = path.join(__dirname, "public");
const LOGS_DIR = path.join(__dirname, "logs");
const ACCESS_LOG_PATH = path.join(LOGS_DIR, "access.log");

if (!DATABASE_URL) {
  throw new Error("Missing DATABASE_URL");
}

if (!PROXY_ADMIN_SECRET) {
  throw new Error("Missing PROXY_ADMIN_SECRET");
}

if (!PROXY_SIGNING_SECRET) {
  throw new Error("Missing PROXY_SIGNING_SECRET");
}

fs.mkdirSync(LOGS_DIR, { recursive: true });

const appPool = new Pool({
  connectionString: DATABASE_URL,
});

const targetPools = new Map();

function appendAccessLog(entry) {
  fs.appendFileSync(ACCESS_LOG_PATH, `${JSON.stringify(entry)}\n`, "utf8");
}

function base64UrlEncode(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlDecode(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = (4 - (normalized.length % 4)) % 4;
  return Buffer.from(normalized + "=".repeat(padding), "base64").toString("utf8");
}

function json(response, statusCode, payload) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
  });
  response.end(JSON.stringify(payload));
}

function sendText(response, statusCode, contentType, payload) {
  response.writeHead(statusCode, {
    "Content-Type": contentType,
  });
  response.end(payload);
}

function safeEqual(a, b) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);

  if (left.length !== right.length) {
    return false;
  }

  return crypto.timingSafeEqual(left, right);
}

function sign(input) {
  return crypto
    .createHmac("sha256", PROXY_SIGNING_SECRET)
    .update(input)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function createToken({ dbName, access, ttlSeconds = 3600 }) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = base64UrlEncode(
    JSON.stringify({
      iat: now,
      exp: now + ttlSeconds,
      db_name: dbName,
      access,
    })
  );
  const signature = sign(`${header}.${payload}`);
  return `${header}.${payload}.${signature}`;
}

async function verifyToken(token) {
  if (!token) {
    throw new Error("Missing token");
  }

  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid token format");
  }

  const [header, payload, signature] = parts;
  const expectedSignature = sign(`${header}.${payload}`);

  if (!safeEqual(signature, expectedSignature)) {
    throw new Error("Invalid token signature");
  }

  const decodedPayload = JSON.parse(base64UrlDecode(payload));
  const now = Math.floor(Date.now() / 1000);

  if (typeof decodedPayload.exp !== "number" || decodedPayload.exp <= now) {
    throw new Error("Token expired");
  }

  if (decodedPayload.access !== "read_only" && decodedPayload.access !== "full") {
    throw new Error("Token access is invalid");
  }

  const targetDatabase = await getManagedDatabase(decodedPayload.db_name);
  if (!targetDatabase) {
    throw new Error("Token database is invalid");
  }

  return decodedPayload;
}

function getBearerToken(request) {
  const header = request.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return null;
  }

  return header.slice("Bearer ".length);
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    let body = "";

    request.on("data", (chunk) => {
      body += chunk;

      if (body.length > 1024 * 1024) {
        request.destroy();
        reject(new Error("Request body too large"));
      }
    });

    request.on("end", () => {
      if (!body) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(body));
      } catch (error) {
        reject(new Error("Invalid JSON body"));
      }
    });

    request.on("error", reject);
  });
}

function notFound(response) {
  json(response, 404, { error: "Not found" });
}

function getClientIp(request) {
  const forwarded = request.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    return forwarded.split(",")[0].trim();
  }

  return request.socket.remoteAddress || null;
}

function normalizeAccess(value) {
  if (value === "read_only" || value === "full") {
    return value;
  }

  throw new Error('access must be "read_only" or "full"');
}

function isReadOnlyQuery(sql) {
  return /^\s*select\b/i.test(sql);
}

function logEvent(type, request, extra = {}) {
  appendAccessLog({
    time: new Date().toISOString(),
    type,
    method: request.method,
    path: request.url,
    ip: getClientIp(request),
    ...extra,
  });
}

function getRecentLogs(limit) {
  if (!fs.existsSync(ACCESS_LOG_PATH)) {
    return [];
  }

  const fileContent = fs.readFileSync(ACCESS_LOG_PATH, "utf8").trim();

  if (!fileContent) {
    return [];
  }

  return fileContent
    .split("\n")
    .slice(-limit)
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch (error) {
        return { raw: line };
      }
    });
}

function getStaticFilePath(pathname) {
  if (pathname === "/") {
    return path.join(PUBLIC_DIR, "index.html");
  }

  if (pathname === "/docs") {
    return path.join(PUBLIC_DIR, "docs.html");
  }

  const cleanPath = pathname.replace(/^\/+/, "");
  return path.join(PUBLIC_DIR, cleanPath);
}

function getContentType(filePath) {
  const extension = path.extname(filePath).toLowerCase();

  if (extension === ".html") return "text/html; charset=utf-8";
  if (extension === ".css") return "text/css; charset=utf-8";
  if (extension === ".js") return "application/javascript; charset=utf-8";
  if (extension === ".json") return "application/json; charset=utf-8";

  return "text/plain; charset=utf-8";
}

function serveStatic(response, pathname) {
  const filePath = getStaticFilePath(pathname);

  if (!filePath.startsWith(PUBLIC_DIR) || !fs.existsSync(filePath)) {
    return false;
  }

  const fileContent = fs.readFileSync(filePath);
  sendText(response, 200, getContentType(filePath), fileContent);
  return true;
}

function requireAdminSecret(request) {
  const adminSecret = request.headers["x-admin-secret"];
  if (!adminSecret || !safeEqual(adminSecret, PROXY_ADMIN_SECRET)) {
    throw new Error("Unauthorized");
  }
}

function normalizeDbName(value) {
  const dbName = typeof value === "string" ? value.trim() : "";

  if (!dbName) {
    throw new Error("Missing db_name");
  }

  if (!/^[a-zA-Z0-9_-]+$/.test(dbName)) {
    throw new Error("db_name may only contain letters, numbers, dash, and underscore");
  }

  return dbName;
}

function normalizeConnectionString(value) {
  const connectionString = typeof value === "string" ? value.trim() : "";

  if (!connectionString) {
    throw new Error("Missing connection_string");
  }

  if (!/^postgres(ql)?:\/\//i.test(connectionString)) {
    throw new Error("connection_string must start with postgres:// or postgresql://");
  }

  return connectionString;
}

function mapDatabaseRow(row, includeConnectionString = false) {
  const mapped = {
    db_name: row.db_name,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };

  if (includeConnectionString) {
    mapped.connection_string = row.connection_string;
  }

  return mapped;
}

async function ensureSchema() {
  await appPool.query(`
    create table if not exists managed_databases (
      db_name text primary key,
      connection_string text not null,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now()
    )
  `);
}

async function listManagedDatabases() {
  const result = await appPool.query(`
    select db_name, connection_string, created_at, updated_at
    from managed_databases
    order by db_name asc
  `);

  return result.rows;
}

async function getManagedDatabase(dbName) {
  const result = await appPool.query(
    `
      select db_name, connection_string, created_at, updated_at
      from managed_databases
      where db_name = $1
    `,
    [dbName]
  );

  return result.rows[0] || null;
}

async function upsertManagedDatabase(dbName, connectionString) {
  const result = await appPool.query(
    `
      insert into managed_databases (db_name, connection_string)
      values ($1, $2)
      on conflict (db_name)
      do update set
        connection_string = excluded.connection_string,
        updated_at = now()
      returning db_name, connection_string, created_at, updated_at
    `,
    [dbName, connectionString]
  );

  return result.rows[0];
}

async function deleteManagedDatabase(dbName) {
  const result = await appPool.query(
    `
      delete from managed_databases
      where db_name = $1
      returning db_name
    `,
    [dbName]
  );

  return result.rowCount > 0;
}

async function getTargetPool(dbName) {
  const managedDatabase = await getManagedDatabase(dbName);

  if (!managedDatabase) {
    throw new Error("Unknown db_name");
  }

  const cached = targetPools.get(dbName);

  if (cached && cached.connectionString === managedDatabase.connection_string) {
    return cached.pool;
  }

  if (cached) {
    await cached.pool.end().catch(() => {});
  }

  const pool = new Pool({
    connectionString: managedDatabase.connection_string,
  });

  targetPools.set(dbName, {
    connectionString: managedDatabase.connection_string,
    pool,
  });

  return pool;
}

async function closeTargetPool(dbName) {
  const cached = targetPools.get(dbName);
  if (!cached) {
    return;
  }

  targetPools.delete(dbName);
  await cached.pool.end().catch(() => {});
}

async function testConnectionString(connectionString) {
  const pool = new Pool({
    connectionString,
  });

  try {
    const result = await pool.query("select current_database() as current_database");
    return result.rows[0];
  } finally {
    await pool.end().catch(() => {});
  }
}

async function handleApiRequest(request, response, pathname, requestUrl) {
  if (request.method === "GET" && pathname === "/api/health") {
    const databases = await listManagedDatabases();
    json(response, 200, {
      ok: true,
      database_count: databases.length,
    });
    return true;
  }

  if (request.method === "GET" && pathname === "/api/databases") {
    const databases = await listManagedDatabases();
    json(response, 200, {
      databases: databases.map((row) => row.db_name),
    });
    return true;
  }

  if (request.method === "GET" && pathname === "/api/managed-databases") {
    requireAdminSecret(request);
    const databases = await listManagedDatabases();
    json(response, 200, {
      databases: databases.map((row) => mapDatabaseRow(row, true)),
    });
    return true;
  }

  if (request.method === "POST" && pathname === "/api/managed-databases") {
    requireAdminSecret(request);
    const body = await readJson(request);
    const dbName = normalizeDbName(body.db_name);
    const connectionString = normalizeConnectionString(body.connection_string);
    const saved = await upsertManagedDatabase(dbName, connectionString);
    await closeTargetPool(dbName);

    logEvent("database_saved", request, { db_name: dbName });

    json(response, 200, {
      database: mapDatabaseRow(saved, true),
    });
    return true;
  }

  if (request.method === "POST" && pathname === "/api/managed-databases/test") {
    requireAdminSecret(request);
    const body = await readJson(request);
    const connectionString = normalizeConnectionString(body.connection_string);
    const result = await testConnectionString(connectionString);

    json(response, 200, {
      ok: true,
      current_database: result.current_database,
    });
    return true;
  }

  if (request.method === "DELETE" && pathname.startsWith("/api/managed-databases/")) {
    requireAdminSecret(request);
    const dbName = normalizeDbName(decodeURIComponent(pathname.split("/").pop()));
    const deleted = await deleteManagedDatabase(dbName);
    await closeTargetPool(dbName);

    if (!deleted) {
      throw new Error("Unknown db_name");
    }

    logEvent("database_deleted", request, { db_name: dbName });

    json(response, 200, {
      ok: true,
      db_name: dbName,
    });
    return true;
  }

  if (request.method === "GET" && pathname === "/api/logs") {
    const limit = Math.max(1, Math.min(Number(requestUrl.searchParams.get("limit")) || 50, 500));
    json(response, 200, { logs: getRecentLogs(limit) });
    return true;
  }

  if (request.method === "POST" && (pathname === "/token" || pathname === "/api/token")) {
    requireAdminSecret(request);
    const body = await readJson(request);
    const dbName = normalizeDbName(body.db_name);
    const access = normalizeAccess(body.access || "read_only");
    const requestedTtl = Number(body.ttl_seconds || 3600);
    const ttlSeconds = Math.max(1, Math.min(requestedTtl, 3600));
    const database = await getManagedDatabase(dbName);

    if (!database) {
      throw new Error("Unknown db_name");
    }

    const token = createToken({ dbName, access, ttlSeconds });

    logEvent("token_issued", request, {
      db_name: dbName,
      access,
      ttl_seconds: ttlSeconds,
    });

    json(response, 200, {
      db_name: dbName,
      access,
      token,
      expiresInSeconds: ttlSeconds,
    });
    return true;
  }

  if (request.method === "POST" && (pathname === "/sql" || pathname === "/api/sql")) {
    const token = getBearerToken(request);
    const claims = await verifyToken(token);
    const body = await readJson(request);
    const dbName = normalizeDbName(body.db_name);
    const sql = typeof body.sql === "string" ? body.sql : "";
    const params = Array.isArray(body.params) ? body.params : [];

    if (claims.db_name !== dbName) {
      throw new Error("Token does not allow this db_name");
    }

    if (!sql.trim()) {
      throw new Error("Missing sql");
    }

    if (claims.access === "read_only" && !isReadOnlyQuery(sql)) {
      logEvent("sql_denied", request, {
        db_name: dbName,
        access: claims.access,
        reason: "read_only_token",
        sql,
      });
      json(response, 403, { error: "This token is read_only" });
      return true;
    }

    const pool = await getTargetPool(dbName);
    const result = await pool.query(sql, params);

    logEvent("sql_ok", request, {
      db_name: dbName,
      access: claims.access,
      command: result.command,
      rowCount: result.rowCount,
      sql,
    });

    json(response, 200, {
      db_name: dbName,
      access: claims.access,
      command: result.command,
      rowCount: result.rowCount,
      rows: result.rows,
    });
    return true;
  }

  return false;
}

async function startServer() {
  await ensureSchema();

  const server = http.createServer(async (request, response) => {
    const requestUrl = new URL(request.url, `http://${request.headers.host || "localhost"}`);
    const pathname = requestUrl.pathname;

    try {
      if (request.method === "GET" && pathname === "/health") {
        const databases = await listManagedDatabases();
        json(response, 200, { ok: true, databases: databases.map((row) => row.db_name) });
        return;
      }

      if (await handleApiRequest(request, response, pathname, requestUrl)) {
        return;
      }

      if (request.method === "GET" && serveStatic(response, pathname)) {
        return;
      }

      notFound(response);
    } catch (error) {
      logEvent("request_error", request, {
        error: error.message || "Unknown error",
      });

      const statusCode =
        error.message === "Unauthorized"
          ? 401
          : error.message === "This token is read_only"
            ? 403
            : error.message === "Request body too large"
              ? 413
              : error.message === "Unknown db_name" || error.message === "Token database is invalid"
                ? 404
                : 400;

      json(response, statusCode, { error: error.message || "Unknown error" });
    }
  });

  server.listen(PORT, () => {
    console.log(`Postgres proxy listening on http://localhost:${PORT}`);
    console.log(`Internal config database: connected`);
    console.log(`Access log: ${ACCESS_LOG_PATH}`);
  });
}

startServer().catch((error) => {
  console.error(error);
  process.exit(1);
});
