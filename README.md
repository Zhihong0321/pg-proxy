# postgres-proxy

Tiny Postgres proxy that keeps your real Postgres passwords inside the proxy and gives clients a short-lived token, a local control UI, and an API docs page.

## 1. Configure

Copy `.env.example` into `.env` and fill in the real values:

```env
PORT=3000
PROXY_ADMIN_SECRET=change-this-admin-secret
PROXY_SIGNING_SECRET=change-this-signing-secret
POSTGRES_DATABASES={"main":"postgres://postgres:postgres@localhost:5432/postgres","analytics":"postgres://postgres:postgres@localhost:5432/analytics"}
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
PROXY_ADMIN_SECRET=change-this-admin-secret
PROXY_SIGNING_SECRET=change-this-signing-secret
POSTGRES_DATABASES={"main":"postgres://user:password@host:5432/db"}
```

Notes:

- Railway injects `PORT`, and this app already listens on it.
- `railway.toml` sets the start command to `npm start`.
- `railway.toml` sets the healthcheck path to `/health`.
- If `POSTGRES_DATABASES` is missing or invalid JSON, Railway will mark the deploy as failed because the app exits on startup.
- Easiest first deploy is one database only, for example `{"main":"postgres://..."}`.

## 3. Mint a token

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

- `db_name`: which configured Postgres to use
- `access`: `read_only` or `full`
- `ttl_seconds`: token lifetime, max 3600

## 4. Use the token for SQL

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

- `db_name`: which configured database to connect to
- `sql`: the SQL text
- `params`: optional query parameters array

## 5. Logs

Every token issue, SQL success, SQL denial, and request error is appended to:

`logs/access.log`

Recent logs are also available from:

`GET /api/logs?limit=50`

## Notes

- The real Postgres passwords stay only inside the proxy through `POSTGRES_DATABASES`.
- Tokens are bound to one `db_name`.
- `read_only` tokens only allow SQL starting with `SELECT`.
- `full` tokens allow any SQL.
