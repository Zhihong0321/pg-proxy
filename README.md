# postgres-proxy

Tiny Postgres proxy that uses one internal Postgres database for app state, and lets you manage AI target databases from the web UI.

## 1. Configure

Copy `.env.example` into `.env` and fill in the real values:

```env
PORT=3000
DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres_proxy
PROXY_ADMIN_SECRET=change-this-admin-secret
PROXY_SIGNING_SECRET=change-this-signing-secret
PROXY_TOKEN_DEFAULT_TTL_SECONDS=3600
# Optional. Leave unset for no owner-side maximum.
# PROXY_TOKEN_MAX_TTL_SECONDS=86400
PUBLIC_PROXY_BASE_URL=https://pg-proxy-production.up.railway.app/
```

## 2. Start

PowerShell:

```powershell
npm start
```

Then open:

- UI: `http://localhost:3000/`
- API docs: `http://localhost:3000/docs`

## Railway

This repo is deployable on Railway with the current setup.

Required Railway variables:

```env
DATABASE_URL=postgres://user:password@host:5432/proxy_app_db
PROXY_ADMIN_SECRET=change-this-admin-secret
PROXY_SIGNING_SECRET=change-this-signing-secret
PROXY_TOKEN_DEFAULT_TTL_SECONDS=3600
# Optional. Leave unset for no owner-side maximum.
# PROXY_TOKEN_MAX_TTL_SECONDS=86400
PUBLIC_PROXY_BASE_URL=https://pg-proxy-production.up.railway.app/
```

Notes:

- Railway injects `PORT`, and this app already listens on it.
- `railway.toml` sets the start command to `npm start`.
- `railway.toml` sets the healthcheck path to `/health`.
- `DATABASE_URL` is the proxy app's own database, not the AI target database.
- Add AI target databases later from the front UI.

## 3. Add target databases in UI

Open `http://localhost:3000/`, enter your admin secret, then save one or more target databases with:

- `db_name`
- `connection_string`

## 4. Mint a token

```powershell
$headers = @{ "x-admin-secret" = "change-this-admin-secret" }
$body = @{
  db_name = "main"
  access = "read_only"
  ttl_seconds = 3600
} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://localhost:3000/token" -Headers $headers -Body $body -ContentType "application/json"
```

Token request fields:

- `db_name`: which saved target database to use
- `access`: `read_only` or `full`
- `ttl_seconds`: token lifetime in seconds. If omitted, `PROXY_TOKEN_DEFAULT_TTL_SECONDS` is used. There is no maximum unless `PROXY_TOKEN_MAX_TTL_SECONDS` is set.

Token responses include an `aiConnectionPacket` field. Paste that whole packet into an AI so it has the proxy URL, API docs URL, database name, access level, and bearer token in one place.

## 5. Use the token for SQL

```powershell
$token = "PUT_TOKEN_HERE"
$headers = @{ Authorization = "Bearer $token" }
$body = @{
  db_name = "main"
  sql = "select now() as now"
  params = @()
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri "http://localhost:3000/sql" -Headers $headers -Body $body -ContentType "application/json"
```

SQL request fields:

- `db_name`: which saved target database to connect to
- `sql`: the SQL text
- `params`: optional query parameters array

## 6. Logs

Every token issue, SQL success, SQL denial, and request error is appended to:

`logs/access.log`

Recent logs are also available from:

`GET /api/logs?limit=50`

## 7. DB Backup (Prod Main → Playground)

Runs a full schema+data copy from `DATABASE_URL_PROD_MAIN` into `DATABASE_URLPLAYGROUND`, entirely inside this server process (via `pg_dump | psql`), triggered by an admin from the web UI or API. Nothing runs on your local machine.

Required Railway variables (source/target are reference variables to your two Postgres services):

```env
DATABASE_URL_PROD_MAIN=${{Postgres-PROD.DATABASE_URL}}
DATABASE_URLPLAYGROUND=${{"POSTGRES Playground".DATABASE_URL}}

# Required so pg_dump/psql exist in the deployed container (Railpack builder):
RAILPACK_DEPLOY_APT_PACKAGES=postgresql-client
```

Usage:

- `POST /api/db-backup` (admin secret required) — starts the backup, returns `202` immediately. Rejects with `409` if one is already running, `400` if the two database variables aren't set.
- `GET /api/db-backup/status` (admin secret required) — poll for `status: idle|running|success|error`, timestamps, duration, and any error message.
- Or use the "DB Backup" panel in the web UI.
- This overwrites Playground's contents every run (`pg_dump --clean --if-exists`).

## Notes

- `DATABASE_URL` is the proxy app database.
- AI target databases are stored in the `managed_databases` table.
- Tokens are bound to one `db_name`.
- `read_only` tokens allow a single `SELECT` statement, including read-only `WITH ... SELECT` CTEs.
- `full` tokens allow any SQL.
- Token lifetime defaults to `PROXY_TOKEN_DEFAULT_TTL_SECONDS`; set `PROXY_TOKEN_MAX_TTL_SECONDS` only if you want an owner-side cap.
- Generated tokens include proxy metadata, and token responses include a paste-ready AI connection packet. `PUBLIC_PROXY_BASE_URL` controls the public URL inside that packet.
