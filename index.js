require("dotenv").config();

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const http = require("http");
const path = require("path");
const { URL } = require("url");
const { spawn } = require("child_process");
const { Pool } = require("pg");

const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL;
const PROXY_ADMIN_SECRET = process.env.PROXY_ADMIN_SECRET;
const PROXY_SIGNING_SECRET = process.env.PROXY_SIGNING_SECRET;
const DB_BACKUP_SOURCE_URL = process.env.DATABASE_URL_PROD_MAIN || null;
const DB_BACKUP_TARGET_URL = process.env.DATABASE_URLPLAYGROUND || null;
const DEFAULT_PUBLIC_PROXY_BASE_URL = "https://pg-proxy-production.up.railway.app/";
const DEFAULT_TOKEN_TTL_SECONDS = parsePositiveIntegerEnv(
  "PROXY_TOKEN_DEFAULT_TTL_SECONDS",
  3600
);
const MAX_TOKEN_TTL_SECONDS = parseOptionalPositiveIntegerEnv("PROXY_TOKEN_MAX_TTL_SECONDS");
const PUBLIC_PROXY_BASE_URL = normalizeOptionalBaseUrl(
  process.env.PUBLIC_PROXY_BASE_URL || DEFAULT_PUBLIC_PROXY_BASE_URL
);
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

function parsePositiveIntegerEnv(name, fallback) {
  const raw = process.env[name];

  if (raw === undefined || raw === "") {
    return fallback;
  }

  const value = Number(raw);
  if (!Number.isInteger(value) || value < 1) {
    throw new Error(`${name} must be a positive integer`);
  }

  return value;
}

function parseOptionalPositiveIntegerEnv(name) {
  const raw = process.env[name];

  if (raw === undefined || raw === "") {
    return null;
  }

  const value = Number(raw);
  if (!Number.isInteger(value) || value < 1) {
    throw new Error(`${name} must be a positive integer`);
  }

  return value;
}

function resolveTokenTtlSeconds(value) {
  const ttlSeconds = value === undefined || value === null || value === ""
    ? DEFAULT_TOKEN_TTL_SECONDS
    : Number(value);

  if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1) {
    throw new Error("ttl_seconds must be a positive integer");
  }

  if (MAX_TOKEN_TTL_SECONDS !== null && ttlSeconds > MAX_TOKEN_TTL_SECONDS) {
    throw new Error(`ttl_seconds must be less than or equal to ${MAX_TOKEN_TTL_SECONDS}`);
  }

  return ttlSeconds;
}

function normalizeOptionalBaseUrl(value) {
  if (!value) {
    return null;
  }

  const parsed = new URL(value);
  parsed.pathname = "/";
  parsed.search = "";
  parsed.hash = "";
  return parsed.toString();
}

function getPublicProxyBaseUrl(request) {
  if (PUBLIC_PROXY_BASE_URL) {
    return PUBLIC_PROXY_BASE_URL;
  }

  const forwardedProto = request.headers["x-forwarded-proto"];
  const forwardedHost = request.headers["x-forwarded-host"];
  const proto = Array.isArray(forwardedProto) ? forwardedProto[0] : forwardedProto;
  const host = Array.isArray(forwardedHost)
    ? forwardedHost[0]
    : forwardedHost || request.headers.host || `localhost:${PORT}`;

  return `${proto || "http"}://${host}/`;
}

function buildTokenContext({ token, dbName, access, ttlSeconds, proxyUrl, docsUrl, profileName }) {
  const sqlUrl = new URL("/api/sql", proxyUrl).toString();
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
  const authorization = `Bearer ${token}`;

  const lines = [
    "POSTGRES PROXY CONNECTION",
    `Proxy URL: ${proxyUrl}`,
    `API docs: ${docsUrl}`,
    `Database: ${dbName}`,
    `Access: ${access}`,
  ];
  if (profileName) {
    lines.push(`Profile: ${profileName} (table-level write limiter active)`);
  }
  lines.push(
    `Expires at: ${expiresAt}`,
    `Authorization header: ${authorization}`,
    `Run SQL with POST ${sqlUrl}`,
    `JSON body example: {"db_name":"${dbName}","sql":"select now() as now","params":[]}`
  );

  return {
    proxyUrl,
    apiDocsUrl: docsUrl,
    sqlUrl,
    authorization,
    expiresAt,
    aiConnectionPacket: lines.join("\n"),
  };
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

function createToken({
  dbName,
  access,
  ttlSeconds = DEFAULT_TOKEN_TTL_SECONDS,
  proxyUrl,
  docsUrl,
  profileName,
}) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payloadObj = {
    iat: now,
    exp: now + ttlSeconds,
    db_name: dbName,
    access,
    proxy_url: proxyUrl,
    api_docs_url: docsUrl,
  };
  if (profileName) {
    payloadObj.profile_name = profileName;
  }
  const payload = base64UrlEncode(JSON.stringify(payloadObj));
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
  const tokens = tokenizeSql(sql);
  let start = 0;

  while (tokens[start] && tokens[start].value === ";") {
    start += 1;
  }

  const end = findStatementEnd(tokens, start);
  if (start === end || !isReadOnlyStatement(tokens, start, end)) {
    return false;
  }

  return tokens.slice(end).every((token) => token.value === ";");
}

function tokenizeSql(sql) {
  const tokens = [];
  let index = 0;

  while (index < sql.length) {
    const char = sql[index];
    const nextChar = sql[index + 1];

    if (/\s/.test(char)) {
      index += 1;
      continue;
    }

    if (char === "-" && nextChar === "-") {
      index += 2;
      while (index < sql.length && sql[index] !== "\n") {
        index += 1;
      }
      continue;
    }

    if (char === "/" && nextChar === "*") {
      index = skipBlockComment(sql, index + 2);
      continue;
    }

    if (char === "'") {
      index = skipQuotedString(sql, index + 1, "'");
      continue;
    }

    if (char === "\"") {
      const end = skipQuotedString(sql, index + 1, "\"");
      tokens.push({ type: "identifier", value: sql.slice(index, end) });
      index = end;
      continue;
    }

    const dollarQuote = sql.slice(index).match(/^\$[A-Za-z_][A-Za-z0-9_]*\$|^\$\$/);
    if (dollarQuote) {
      const marker = dollarQuote[0];
      const end = sql.indexOf(marker, index + marker.length);
      index = end === -1 ? sql.length : end + marker.length;
      continue;
    }

    if (/[A-Za-z_]/.test(char)) {
      const start = index;
      index += 1;
      while (index < sql.length && /[A-Za-z0-9_$]/.test(sql[index])) {
        index += 1;
      }
      tokens.push({ type: "word", value: sql.slice(start, index).toLowerCase() });
      continue;
    }

    if ("(),;".includes(char)) {
      tokens.push({ type: "symbol", value: char });
    }

    index += 1;
  }

  return tokens;
}

function skipBlockComment(sql, index) {
  let depth = 1;

  while (index < sql.length && depth > 0) {
    if (sql[index] === "/" && sql[index + 1] === "*") {
      depth += 1;
      index += 2;
      continue;
    }

    if (sql[index] === "*" && sql[index + 1] === "/") {
      depth -= 1;
      index += 2;
      continue;
    }

    index += 1;
  }

  return index;
}

function skipQuotedString(sql, index, quote) {
  while (index < sql.length) {
    if (sql[index] === quote) {
      if (sql[index + 1] === quote) {
        index += 2;
        continue;
      }

      return index + 1;
    }

    index += 1;
  }

  return index;
}

function findStatementEnd(tokens, start) {
  let depth = 0;

  for (let index = start; index < tokens.length; index += 1) {
    const token = tokens[index];

    if (token.value === "(") {
      depth += 1;
    } else if (token.value === ")") {
      depth = Math.max(0, depth - 1);
    } else if (token.value === ";" && depth === 0) {
      return index;
    }
  }

  return tokens.length;
}

function isReadOnlyStatement(tokens, start, end) {
  const firstToken = tokens[start];

  if (!firstToken || firstToken.type !== "word") {
    return false;
  }

  if (firstToken.value === "select") {
    return true;
  }

  if (firstToken.value === "with") {
    return isReadOnlyWithStatement(tokens, start, end);
  }

  return false;
}

function isReadOnlyWithStatement(tokens, start, end) {
  let index = start + 1;

  if (isKeyword(tokens[index], "recursive")) {
    index += 1;
  }

  while (index < end) {
    if (!isIdentifierToken(tokens[index])) {
      return false;
    }
    index += 1;

    if (tokens[index] && tokens[index].value === "(") {
      index = findMatchingParen(tokens, index, end) + 1;
      if (index === 0) {
        return false;
      }
    }

    if (!isKeyword(tokens[index], "as")) {
      return false;
    }
    index += 1;

    if (isKeyword(tokens[index], "not") && isKeyword(tokens[index + 1], "materialized")) {
      index += 2;
    } else if (isKeyword(tokens[index], "materialized")) {
      index += 1;
    }

    if (!tokens[index] || tokens[index].value !== "(") {
      return false;
    }

    const bodyStart = index + 1;
    const bodyEnd = findMatchingParen(tokens, index, end);
    if (bodyEnd === -1 || !isReadOnlyStatement(tokens, bodyStart, bodyEnd)) {
      return false;
    }

    index = bodyEnd + 1;

    while (index < end) {
      if (tokens[index].value === ",") {
        index += 1;
        break;
      }

      if (isStatementKeyword(tokens[index])) {
        return tokens[index].value === "select";
      }

      index += 1;
    }
  }

  return false;
}

function isIdentifierToken(token) {
  return token && (token.type === "word" || token.type === "identifier");
}

function isKeyword(token, keyword) {
  return token && token.type === "word" && token.value === keyword;
}

function isStatementKeyword(token) {
  return (
    token &&
    token.type === "word" &&
    ["select", "insert", "update", "delete", "merge", "values", "with"].includes(token.value)
  );
}

function findMatchingParen(tokens, start, end) {
  let depth = 0;

  for (let index = start; index < end; index += 1) {
    if (tokens[index].value === "(") {
      depth += 1;
    } else if (tokens[index].value === ")") {
      depth -= 1;
      if (depth === 0) {
        return index;
      }
    }
  }

  return -1;
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

  if (pathname === "/ai-context") {
    return path.join(PUBLIC_DIR, "ai-context.md");
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
  if (extension === ".md") return "text/markdown; charset=utf-8";

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

  await appPool.query(`
    create table if not exists access_profiles (
      id serial primary key,
      db_name text not null references managed_databases(db_name) on delete cascade,
      profile_name text not null,
      allowed_tables text[] not null default '{}',
      denied_tables text[] not null default '{}',
      description text not null default '',
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now(),
      unique(db_name, profile_name)
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

// --- DB Backup (Prod Main -> Playground, run inside this app on Railway) ---

const dbBackupState = {
  status: "idle", // idle | running | success | error
  startedAt: null,
  finishedAt: null,
  durationMs: null,
  error: null,
};

let dbBackupRunning = false;

function redactSecrets(text) {
  if (!text) {
    return text;
  }

  return text.replace(/postgres(?:ql)?:\/\/[^\s'"]+/gi, "postgres://[redacted]");
}

function runChildProcess(command, args) {
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });

    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });

    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });

    child.on("error", (error) => {
      resolve({ code: -1, stdout, stderr: stderr || error.message });
    });

    child.on("close", (code) => {
      resolve({ code, stdout, stderr });
    });
  });
}

async function dumpDatabase(connectionString, filePath) {
  const args = ["--no-owner", "--no-privileges", "--clean", "--if-exists", "-f", filePath, connectionString];
  const result = await runChildProcess("pg_dump", args);

  if (result.code !== 0) {
    throw new Error(`pg_dump failed (exit ${result.code}): ${redactSecrets(result.stderr).slice(0, 2000)}`);
  }
}

async function restoreDatabase(connectionString, filePath) {
  const args = ["-v", "ON_ERROR_STOP=1", "-X", "-q", "-f", filePath, connectionString];
  const result = await runChildProcess("psql", args);

  if (result.code !== 0) {
    throw new Error(`psql restore failed (exit ${result.code}): ${redactSecrets(result.stderr).slice(0, 2000)}`);
  }
}

async function runDbBackup() {
  if (dbBackupRunning) {
    throw new Error("A backup is already running");
  }

  dbBackupRunning = true;
  dbBackupState.status = "running";
  dbBackupState.startedAt = new Date().toISOString();
  dbBackupState.finishedAt = null;
  dbBackupState.durationMs = null;
  dbBackupState.error = null;

  const startedAtMs = Date.now();
  const dumpFilePath = path.join(os.tmpdir(), `pg-proxy-db-backup-${startedAtMs}.sql`);

  try {
    if (!DB_BACKUP_SOURCE_URL || !DB_BACKUP_TARGET_URL) {
      throw new Error("DATABASE_URL_PROD_MAIN and DATABASE_URLPLAYGROUND must both be set");
    }

    if (DB_BACKUP_SOURCE_URL === DB_BACKUP_TARGET_URL) {
      throw new Error("Source and target connection strings are identical; refusing to copy a database into itself");
    }

    await dumpDatabase(DB_BACKUP_SOURCE_URL, dumpFilePath);
    await restoreDatabase(DB_BACKUP_TARGET_URL, dumpFilePath);
    dbBackupState.status = "success";
    appendAccessLog({
      time: new Date().toISOString(),
      type: "db_backup_completed",
      durationMs: Date.now() - startedAtMs,
    });
  } catch (error) {
    dbBackupState.status = "error";
    dbBackupState.error = redactSecrets(error.message || "Unknown error");
    appendAccessLog({
      time: new Date().toISOString(),
      type: "db_backup_failed",
      error: dbBackupState.error,
    });
    throw error;
  } finally {
    dbBackupState.finishedAt = new Date().toISOString();
    dbBackupState.durationMs = Date.now() - startedAtMs;
    dbBackupRunning = false;
    fs.unlink(dumpFilePath, () => {});
  }
}

// --- Access Profiles ---

async function listAccessProfiles(dbName) {
  const result = await appPool.query(
    `select * from access_profiles where db_name = $1 order by profile_name asc`,
    [dbName]
  );
  return result.rows;
}

async function getAccessProfile(dbName, profileName) {
  const result = await appPool.query(
    `select * from access_profiles where db_name = $1 and profile_name = $2`,
    [dbName, profileName]
  );
  return result.rows[0] || null;
}

async function upsertAccessProfile(dbName, profileName, { allowedTables, deniedTables, description }) {
  const result = await appPool.query(
    `insert into access_profiles (db_name, profile_name, allowed_tables, denied_tables, description)
     values ($1, $2, $3, $4, $5)
     on conflict (db_name, profile_name)
     do update set
       allowed_tables = excluded.allowed_tables,
       denied_tables = excluded.denied_tables,
       description = excluded.description,
       updated_at = now()
     returning *`,
    [dbName, profileName, allowedTables || [], deniedTables || [], description || ""]
  );
  return result.rows[0];
}

async function deleteAccessProfile(dbName, profileName) {
  const result = await appPool.query(
    `delete from access_profiles where db_name = $1 and profile_name = $2 returning *`,
    [dbName, profileName]
  );
  return result.rowCount > 0;
}

async function introspectTables(dbName) {
  const pool = await getTargetPool(dbName);
  const result = await pool.query(`
    select table_schema, table_name, table_type
    from information_schema.tables
    where table_schema not in ('pg_catalog', 'information_schema')
    order by table_schema, table_name
  `);
  return result.rows;
}

function extractTargetTables(sql) {
  const tables = new Set();
  const normalized = sql.replace(/--[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");

  const insertMatch = normalized.match(/\binsert\s+into\s+(?:only\s+)?([^\s(]+)/gi);
  if (insertMatch) {
    for (const m of insertMatch) {
      const table = m.replace(/\binsert\s+into\s+(?:only\s+)?/i, "").trim().replace(/"/g, "").toLowerCase();
      tables.add(table);
    }
  }

  const updateMatch = normalized.match(/\bupdate\s+(?:only\s+)?([^\s]+)/gi);
  if (updateMatch) {
    for (const m of updateMatch) {
      const table = m.replace(/\bupdate\s+(?:only\s+)?/i, "").trim().replace(/"/g, "").toLowerCase();
      tables.add(table);
    }
  }

  const deleteMatch = normalized.match(/\bdelete\s+from\s+(?:only\s+)?([^\s]+)/gi);
  if (deleteMatch) {
    for (const m of deleteMatch) {
      const table = m.replace(/\bdelete\s+from\s+(?:only\s+)?/i, "").trim().replace(/"/g, "").toLowerCase();
      tables.add(table);
    }
  }

  const truncateMatch = normalized.match(/\btruncate\s+(?:table\s+)?(?:only\s+)?([^\s;,]+)/gi);
  if (truncateMatch) {
    for (const m of truncateMatch) {
      const table = m.replace(/\btruncate\s+(?:table\s+)?(?:only\s+)?/i, "").trim().replace(/"/g, "").toLowerCase();
      tables.add(table);
    }
  }

  return [...tables];
}

function checkTableAccess(sql, profile) {
  if (isReadOnlyQuery(sql)) {
    return { allowed: true };
  }

  const targetTables = extractTargetTables(sql);

  if (targetTables.length === 0) {
    return { allowed: false, reason: "Cannot determine target table for write operation" };
  }

  const allowedSet = new Set((profile.allowed_tables || []).map((t) => t.toLowerCase()));
  const deniedSet = new Set((profile.denied_tables || []).map((t) => t.toLowerCase()));

  for (const table of targetTables) {
    const tableName = table.includes(".") ? table.split(".").pop() : table;
    const fullName = table;

    if (deniedSet.has(fullName) || deniedSet.has(tableName)) {
      return { allowed: false, reason: `Table '${table}' is explicitly denied by profile '${profile.profile_name}'` };
    }

    if (allowedSet.size > 0) {
      if (!allowedSet.has(fullName) && !allowedSet.has(tableName)) {
        return { allowed: false, reason: `Table '${table}' is not in the allowed list for profile '${profile.profile_name}'` };
      }
    }
  }

  return { allowed: true };
}

function generateAiProfile(tables, description) {
  const desc = description.toLowerCase();
  const allowedTables = [];
  const deniedTables = [];

  for (const table of tables) {
    const fullName = table.table_schema === "public"
      ? table.table_name
      : `${table.table_schema}.${table.table_name}`;

    if (table.table_type === "VIEW") {
      continue;
    }

    const isSystem = /migration|schema_version|knex_|flyway_|pgmigration/i.test(table.table_name);
    const isSensitive = /user|account|auth|credential|password|secret|token|session|permission|role/i.test(table.table_name);

    if (isSystem) {
      deniedTables.push(fullName);
      continue;
    }

    if (desc.includes("full") || desc.includes("all")) {
      if (isSensitive) {
        deniedTables.push(fullName);
      } else {
        allowedTables.push(fullName);
      }
      continue;
    }

    if (desc.includes(table.table_name.toLowerCase()) || desc.includes(fullName.toLowerCase())) {
      allowedTables.push(fullName);
      continue;
    }

    if (desc.includes("read") && !desc.includes("write")) {
      continue;
    }

    if (isSensitive) {
      deniedTables.push(fullName);
    }
  }

  return { allowedTables, deniedTables };
}

async function handleApiRequest(request, response, pathname, requestUrl) {
  if (request.method === "GET" && pathname === "/api/health") {
    let configDbOk = false;
    let configDbError = null;
    try {
      await appPool.query("select current_database() as db_name, now() as server_time");
      configDbOk = true;
    } catch (err) {
      configDbError = err.message;
    }

    const databases = configDbOk ? await listManagedDatabases() : [];
    let profileCount = 0;
    try {
      if (configDbOk) {
        const r = await appPool.query("select count(*)::int as count from access_profiles");
        profileCount = r.rows[0].count;
      }
    } catch (e) {
      // table may not exist yet, that's fine
    }

    json(response, 200, {
      ok: configDbOk,
      config_db: {
        status: configDbOk ? "healthy" : "error",
        error: configDbError,
      },
      database_count: databases.length,
      profile_count: profileCount,
      schema_initialized: configDbOk,
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

  if (request.method === "POST" && pathname === "/api/db-backup") {
    requireAdminSecret(request);

    if (dbBackupRunning) {
      json(response, 409, { error: "A backup is already running", status: dbBackupState.status });
      return true;
    }

    if (!DB_BACKUP_SOURCE_URL || !DB_BACKUP_TARGET_URL) {
      json(response, 400, { error: "DATABASE_URL_PROD_MAIN and DATABASE_URLPLAYGROUND must both be set" });
      return true;
    }

    logEvent("db_backup_started", request);
    runDbBackup().catch(() => {});

    json(response, 202, { ok: true, status: "running" });
    return true;
  }

  if (request.method === "GET" && pathname === "/api/db-backup/status") {
    requireAdminSecret(request);

    json(response, 200, {
      ...dbBackupState,
      configured: Boolean(DB_BACKUP_SOURCE_URL && DB_BACKUP_TARGET_URL),
    });
    return true;
  }

  if (request.method === "GET" && pathname === "/api/logs") {
    const limit = Math.max(1, Math.min(Number(requestUrl.searchParams.get("limit")) || 50, 500));
    json(response, 200, { logs: getRecentLogs(limit) });
    return true;
  }

  // --- Access Profiles API ---

  if (request.method === "GET" && pathname === "/api/access-profiles") {
    requireAdminSecret(request);
    const dbName = requestUrl.searchParams.get("db_name");
    if (!dbName) {
      throw new Error("Missing db_name query parameter");
    }
    const profiles = await listAccessProfiles(dbName);
    json(response, 200, { profiles });
    return true;
  }

  if (request.method === "GET" && pathname.startsWith("/api/access-profiles/")) {
    requireAdminSecret(request);
    const parts = pathname.split("/").filter(Boolean);
    const dbName = requestUrl.searchParams.get("db_name");
    const profileName = decodeURIComponent(parts[2] || "");
    if (!dbName) {
      throw new Error("Missing db_name query parameter");
    }
    const profile = await getAccessProfile(dbName, profileName);
    if (!profile) {
      throw new Error("Profile not found");
    }
    json(response, 200, { profile });
    return true;
  }

  if (request.method === "POST" && pathname === "/api/access-profiles") {
    requireAdminSecret(request);
    const body = await readJson(request);
    const dbName = normalizeDbName(body.db_name);
    const profileName = (body.profile_name || "").trim();
    if (!profileName || !/^[a-zA-Z0-9_-]+$/.test(profileName)) {
      throw new Error("profile_name must be alphanumeric with dashes/underscores");
    }
    const database = await getManagedDatabase(dbName);
    if (!database) {
      throw new Error("Unknown db_name");
    }
    const saved = await upsertAccessProfile(dbName, profileName, {
      allowedTables: body.allowed_tables || [],
      deniedTables: body.denied_tables || [],
      description: body.description || "",
    });
    logEvent("profile_saved", request, { db_name: dbName, profile_name: profileName });
    json(response, 200, { profile: saved });
    return true;
  }

  if (request.method === "DELETE" && pathname.startsWith("/api/access-profiles/")) {
    requireAdminSecret(request);
    const parts = pathname.split("/").filter(Boolean);
    const profileName = decodeURIComponent(parts[2] || "");
    const dbName = requestUrl.searchParams.get("db_name");
    if (!dbName) {
      throw new Error("Missing db_name query parameter");
    }
    const deleted = await deleteAccessProfile(dbName, profileName);
    if (!deleted) {
      throw new Error("Profile not found");
    }
    logEvent("profile_deleted", request, { db_name: dbName, profile_name: profileName });
    json(response, 200, { ok: true, db_name: dbName, profile_name: profileName });
    return true;
  }

  if (request.method === "POST" && pathname === "/api/access-profiles/generate") {
    requireAdminSecret(request);
    const body = await readJson(request);
    const dbName = normalizeDbName(body.db_name);
    const description = (body.description || "").trim();
    if (!description) {
      throw new Error("Missing description");
    }
    const database = await getManagedDatabase(dbName);
    if (!database) {
      throw new Error("Unknown db_name");
    }
    const tables = await introspectTables(dbName);
    const generated = generateAiProfile(tables, description);
    json(response, 200, {
      db_name: dbName,
      description,
      tables: tables.map((t) => `${t.table_schema}.${t.table_name} (${t.table_type})`),
      suggested_profile: {
        allowed_tables: generated.allowedTables,
        denied_tables: generated.deniedTables,
      },
    });
    return true;
  }

  if (request.method === "GET" && pathname === "/api/introspect-tables") {
    requireAdminSecret(request);
    const dbName = requestUrl.searchParams.get("db_name");
    if (!dbName) {
      throw new Error("Missing db_name query parameter");
    }
    const database = await getManagedDatabase(dbName);
    if (!database) {
      throw new Error("Unknown db_name");
    }
    const tables = await introspectTables(dbName);
    json(response, 200, { db_name: dbName, tables });
    return true;
  }

  if (request.method === "POST" && (pathname === "/token" || pathname === "/api/token")) {
    requireAdminSecret(request);
    const body = await readJson(request);
    const dbName = normalizeDbName(body.db_name);
    const access = normalizeAccess(body.access || "read_only");
    const ttlSeconds = resolveTokenTtlSeconds(body.ttl_seconds);
    const profileName = body.profile_name || null;
    const database = await getManagedDatabase(dbName);

    if (!database) {
      throw new Error("Unknown db_name");
    }

    if (profileName) {
      const profile = await getAccessProfile(dbName, profileName);
      if (!profile) {
        throw new Error(`Unknown profile '${profileName}' for database '${dbName}'`);
      }
    }

    const proxyUrl = getPublicProxyBaseUrl(request);
    const docsUrl = new URL("/docs", proxyUrl).toString();
    const token = createToken({ dbName, access, ttlSeconds, proxyUrl, docsUrl, profileName });
    const tokenContext = buildTokenContext({
      token,
      dbName,
      access,
      ttlSeconds,
      proxyUrl,
      docsUrl,
      profileName,
    });

    logEvent("token_issued", request, {
      db_name: dbName,
      access,
      profile_name: profileName,
      ttl_seconds: ttlSeconds,
    });

    json(response, 200, {
      db_name: dbName,
      access,
      profile_name: profileName,
      token,
      expiresInSeconds: ttlSeconds,
      proxyUrl: tokenContext.proxyUrl,
      apiDocsUrl: tokenContext.apiDocsUrl,
      sqlUrl: tokenContext.sqlUrl,
      authorization: tokenContext.authorization,
      expiresAt: tokenContext.expiresAt,
      aiConnectionPacket: tokenContext.aiConnectionPacket,
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

    if (claims.profile_name && claims.access === "full") {
      const profile = await getAccessProfile(dbName, claims.profile_name);
      if (profile) {
        const accessCheck = checkTableAccess(sql, profile);
        if (!accessCheck.allowed) {
          logEvent("sql_denied", request, {
            db_name: dbName,
            access: claims.access,
            profile_name: claims.profile_name,
            reason: accessCheck.reason,
            sql,
          });
          json(response, 403, { error: accessCheck.reason });
          return true;
        }
      }
    }

    const pool = await getTargetPool(dbName);
    const result = await pool.query(sql, params);

    logEvent("sql_ok", request, {
      db_name: dbName,
      access: claims.access,
      profile_name: claims.profile_name || null,
      command: result.command,
      rowCount: result.rowCount,
      sql,
    });

    json(response, 200, {
      db_name: dbName,
      access: claims.access,
      profile_name: claims.profile_name || null,
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

if (require.main === module) {
  startServer().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}

module.exports = {
  isReadOnlyQuery,
};
