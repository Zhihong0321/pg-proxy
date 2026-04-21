require("dotenv").config();

const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const path = require("path");
const { URL } = require("url");
const { Pool } = require("pg");

const PORT = Number(process.env.PORT || 3000);
const PROXY_ADMIN_SECRET = process.env.PROXY_ADMIN_SECRET;
const PROXY_SIGNING_SECRET = process.env.PROXY_SIGNING_SECRET;
const DATABASES_JSON = process.env.POSTGRES_DATABASES;
const DATABASE_URL = process.env.DATABASE_URL;
const PUBLIC_DIR = path.join(__dirname, "public");

if (!PROXY_ADMIN_SECRET) {
  throw new Error("Missing PROXY_ADMIN_SECRET");
}

if (!PROXY_SIGNING_SECRET) {
  throw new Error("Missing PROXY_SIGNING_SECRET");
}

const databases = parseDatabases(DATABASES_JSON || DATABASE_URL);
const pools = new Map(
  Object.entries(databases).map(([dbName, connectionString]) => [
    dbName,
    new Pool({ connectionString }),
  ])
);

const logsDir = path.join(__dirname, "logs");
const accessLogPath = path.join(logsDir, "access.log");

fs.mkdirSync(logsDir, { recursive: true });

function parseDatabases(value) {
  const normalizedValue = normalizeDatabaseConfigValue(value);

  if (!normalizedValue) {
    throw new Error("Missing POSTGRES_DATABASES or DATABASE_URL");
  }

  if (looksLikeConnectionString(normalizedValue)) {
    return { main: normalizedValue };
  }

  const keyValuePairs = parseKeyValueDatabaseList(normalizedValue);
  if (keyValuePairs) {
    return keyValuePairs;
  }

  let parsed;

  try {
    parsed = JSON.parse(normalizedValue);
  } catch (error) {
    throw new Error(
      "POSTGRES_DATABASES must be valid JSON, a single postgres:// URL, or db_name=postgres://..."
    );
  }

  if (typeof parsed === "string" && looksLikeConnectionString(parsed)) {
    return { main: parsed };
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("POSTGRES_DATABASES must be an object");
  }

  const entries = Object.entries(parsed);

  if (entries.length === 0) {
    throw new Error("POSTGRES_DATABASES must include at least one database");
  }

  for (const [dbName, connectionString] of entries) {
    if (!dbName.trim()) {
      throw new Error("Database names must not be empty");
    }

    if (typeof connectionString !== "string" || !connectionString.trim()) {
      throw new Error(`Database "${dbName}" must have a connection string`);
    }
  }

  return parsed;
}

function normalizeDatabaseConfigValue(value) {
  if (typeof value !== "string") {
    return "";
  }

  const trimmed = value.trim();

  if (!trimmed) {
    return "";
  }

  const hasWrappingSingleQuotes = trimmed.startsWith("'") && trimmed.endsWith("'");
  const hasWrappingDoubleQuotes = trimmed.startsWith('"') && trimmed.endsWith('"');

  if (hasWrappingSingleQuotes || hasWrappingDoubleQuotes) {
    return trimmed.slice(1, -1).trim();
  }

  return trimmed;
}

function looksLikeConnectionString(value) {
  return /^postgres(ql)?:\/\//i.test(value);
}

function parseKeyValueDatabaseList(value) {
  if (!value.includes("=")) {
    return null;
  }

  const parts = value
    .split(/\r?\n|,(?=[^,=]+=)/)
    .map((item) => item.trim())
    .filter(Boolean);

  if (parts.length === 0) {
    return null;
  }

  const databases = {};

  for (const part of parts) {
    const separatorIndex = part.indexOf("=");
    if (separatorIndex <= 0) {
      return null;
    }

    const dbName = part.slice(0, separatorIndex).trim();
    const connectionString = part.slice(separatorIndex + 1).trim();

    if (!dbName || !looksLikeConnectionString(connectionString)) {
      return null;
    }

    databases[dbName] = connectionString;
  }

  return Object.keys(databases).length > 0 ? databases : null;
}

function appendAccessLog(entry) {
  fs.appendFileSync(accessLogPath, `${JSON.stringify(entry)}\n`, "utf8");
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

function verifyToken(token) {
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

  if (!decodedPayload.db_name || !databases[decodedPayload.db_name]) {
    throw new Error("Token database is invalid");
  }

  if (decodedPayload.access !== "read_only" && decodedPayload.access !== "full") {
    throw new Error("Token access is invalid");
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

function getPool(dbName) {
  const pool = pools.get(dbName);

  if (!pool) {
    throw new Error("Unknown db_name");
  }

  return pool;
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
  if (!fs.existsSync(accessLogPath)) {
    return [];
  }

  const fileContent = fs.readFileSync(accessLogPath, "utf8").trim();

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

const server = http.createServer(async (request, response) => {
  const requestUrl = new URL(request.url, `http://${request.headers.host || "localhost"}`);
  const pathname = requestUrl.pathname;

  try {
    if (request.method === "GET" && pathname === "/health") {
      json(response, 200, { ok: true, databases: Object.keys(databases) });
      return;
    }

    if (request.method === "GET" && pathname === "/api/health") {
      json(response, 200, { ok: true, databases: Object.keys(databases) });
      return;
    }

    if (request.method === "GET" && pathname === "/api/databases") {
      json(response, 200, { databases: Object.keys(databases) });
      return;
    }

    if (request.method === "GET" && pathname === "/api/logs") {
      const limit = Math.max(1, Math.min(Number(requestUrl.searchParams.get("limit")) || 50, 500));
      json(response, 200, { logs: getRecentLogs(limit) });
      return;
    }

    if (
      request.method === "POST" &&
      (pathname === "/token" || pathname === "/api/token")
    ) {
      const adminSecret = request.headers["x-admin-secret"];

      if (!adminSecret || !safeEqual(adminSecret, PROXY_ADMIN_SECRET)) {
        logEvent("token_denied", request);
        json(response, 401, { error: "Unauthorized" });
        return;
      }

      const body = await readJson(request);
      const dbName = typeof body.db_name === "string" ? body.db_name.trim() : "";
      const access = normalizeAccess(body.access || "read_only");
      const requestedTtl = Number(body.ttl_seconds || 3600);
      const ttlSeconds = Math.max(1, Math.min(requestedTtl, 3600));

      if (!dbName) {
        throw new Error("Missing db_name");
      }

      if (!databases[dbName]) {
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
      return;
    }

    if (
      request.method === "POST" &&
      (pathname === "/sql" || pathname === "/api/sql")
    ) {
      const token = getBearerToken(request);
      const claims = verifyToken(token);
      const body = await readJson(request);
      const dbName = typeof body.db_name === "string" ? body.db_name.trim() : "";
      const sql = typeof body.sql === "string" ? body.sql : "";
      const params = Array.isArray(body.params) ? body.params : [];

      if (!dbName) {
        throw new Error("Missing db_name");
      }

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
        return;
      }

      const pool = getPool(dbName);
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
            : 400;

    json(response, statusCode, { error: error.message || "Unknown error" });
  }
});

server.listen(PORT, () => {
  console.log(`Postgres proxy listening on http://localhost:${PORT}`);
  console.log(`Configured databases: ${Object.keys(databases).join(", ")}`);
  console.log(`Access log: ${accessLogPath}`);
});
