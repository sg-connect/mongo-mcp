# mongo-mcp

A **read-only** MongoDB MCP server that you host yourself. Claude gets a URL,
a username and a password. It never sees the connection strings, and it cannot
write, even when the database user inside the server can.

```
Claude (Claude Code)
  │  HTTPS + username/password
  ▼
VM ── Caddy (TLS, only /mcp is public)
        ▼
      mongo-mcp (container, not published to the network)
        ├─ auth: per-user scrypt-hashed passwords, lockout after failed logins
        ├─ allowlists: connection → database → collection
        ├─ validation: stage allowlist, no $out/$merge, no server-side JavaScript
        ├─ limits: ≤ 100 docs, maxTimeMS, output size cap, full-scan refusal on production
        ├─ read-only driver facades + a tripwire on any non-read command
        └─ audit log: who ran what, redacted
        ▼
      MongoDB clusters (connection strings in .env.sandbox / .env.production on the VM)
```

> Review the code before pointing it at data you care about. MIT licensed.

---

## Tools

| Tool | What it returns |
|---|---|
| `list-connections` | The named connections, their allowlists and limits, and whether credentials are set. Never the connection string. |
| `list-databases` | Allowlisted databases that exist on a connection. |
| `list-collections` | Allowlisted collections in a database, with estimated counts. |
| `collection-indexes` | Index definitions. |
| `collection-schema` | Field paths, BSON types and how often each appears, inferred from a sample. No values. |
| `collection-storage-size` | Document count, data size, storage size and index sizes. |
| `db-stats` | Collection, object and index counts and sizes for a database. |
| `find` | Documents matching a filter, with projection, sort, skip and hint. At most 100. |
| `count` | Exact count for a filter, or the metadata estimate when the filter is empty. |
| `aggregate` | Read-only pipelines. Stages are allowlisted, and a `$limit` is always appended. |
| `explain` | The query plan for a find, count or aggregate. |

There are no insert, update, delete, drop, create, rename or index tools, no
`runCommand`, and no way to run JavaScript. Claude selects a cluster by
connection name; there is no `connect` tool that takes a connection string.

Inputs and outputs use Extended JSON: `{"_id": {"$oid": "65f1…"}}`,
`{"createdAt": {"$gte": {"$date": "2026-01-01T00:00:00Z"}}}`.

## Why Claude cannot write, even with a read-write user

Each layer is enough on its own, and each has tests (`tests/integration.test.ts`
runs every write-shaped request through a user that *can* write and checks the
database is unchanged afterwards):

1. **No write tools exist.** The tool list is closed (`src/tools/index.ts`).
2. **Validation.** `$out`, `$merge`, `$currentOp` and other unsafe stages are
   refused, including inside `$facet`, `$lookup` and `$unionWith`. So are
   `$where`, `$function` and `$accumulator`.
3. **Read-only facades.** Tools receive objects with only `find`, `aggregate`,
   `countDocuments`, `indexes` and similar reads. Write methods are missing from
   those objects, and the facade refuses `$out`/`$merge` independently of step 2.
4. **Tripwire.** Every command the driver sends is compared with a read
   allowlist. Anything else is logged as a `SECURITY` event.

A read-only database user (Atlas built-in role `read`) is still the better
choice where possible. It turns a bug in this server into a permission error
instead of a write.

---

## Running it on a VM (Windows)

The VM needs **Docker Desktop**, a DNS name pointing at it (for example
`mongo-mcp.example.com`), and inbound TCP **80 and 443** open. Caddy uses port 80
to get the TLS certificate. Nothing else needs to be reachable. Claude does not
need access to the VM itself.

In PowerShell, in the repository folder:

```powershell
# 1. Settings and secrets (all git-ignored)
Copy-Item .env.example .env                        # set MCP_DOMAIN
Copy-Item .env.sandbox.example .env.sandbox        # sandbox connection strings
Copy-Item .env.production.example .env.production  # production connection strings
Copy-Item config\connections.example.json config\connections.json
Copy-Item config\users.example.json config\users.json
notepad .env; notepad .env.sandbox; notepad .env.production; notepad config\connections.json

# 2. Build, then create an account per person (the password is typed, not echoed)
docker compose build
docker run --rm -it mongo-mcp:local node dist/cli.js --hash-password alice
#   → paste the printed  "alice": "scrypt$…"  line into config\users.json

# 3. Check the configuration and every connection (prints no secrets)
docker compose run --rm mcp node dist/cli.js --check

# 4. Start
docker compose up -d
docker compose logs -f mcp
```

To add a cluster:
1. Add a variable to `.env.sandbox` or `.env.production`, for example `PRODUCTION_CLUSTER1_URI=mongodb+srv://…`.
2. Add a matching entry to `config/connections.json`.
3. Run `docker compose up -d --force-recreate mcp`.

To add or remove a person, edit `config/users.json` and then run
`docker compose restart mcp`.

### `config/connections.json`

```json
{
  "production-cluster0": {
    "uriEnv": "PRODUCTION_CLUSTER0_URI",
    "production": true,
    "allowedDatabases": ["example_db"],
    "allowedCollections": ["orders", "customers"]
  }
}
```

| Field | Default | Meaning |
|---|---|---|
| `uriEnv` | required | Name of the variable holding the connection string. A connection string here is refused. |
| `allowedDatabases` | required | Databases Claude may read. |
| `allowedCollections` | required | Collections Claude may read. `["*"]` only works when `production` is false. |
| `production` | true if the name contains "prod" | Turns on full-scan refusal and secondary reads. |
| `defaultLimit` / `maxLimit` | 20 / 100 | Documents per result. The hard cap is 100. |
| `maxTimeMS` | 10000 | Server-side time budget. The hard cap is 30000. |
| `rejectCollscan` / `collscanMaxDocs` | = `production` / 10000 | Refuse queries that would scan a whole collection larger than this. |
| `readPreference` | `secondaryPreferred` on production | Driver read preference. |

### Without Docker

You need Node 20.12 or later. From PowerShell:

```powershell
npm ci --legacy-peer-deps
npm run build
node dist\cli.js --check
$env:MONGO_MCP_HTTP_ALLOWED_HOSTS = "mongo-mcp.example.com"
node dist\cli.js --host 127.0.0.1
```

The server reads `.env`, `.env.sandbox` and `.env.production` from the
repository folder. It speaks plain HTTP, so put a TLS proxy in front (for
example Caddy for Windows with `deploy/Caddyfile`), and set
`MONGO_MCP_TRUST_PROXY=1` so it refuses any request that didn't arrive over HTTPS.

---

## Connecting Claude Code

Every person uses their own account, so the audit log shows who ran what.

```bash
# macOS / Linux
AUTH=$(printf 'alice:<password>' | base64)
claude mcp add --transport http mongo https://mongo-mcp.example.com/mcp --header "Authorization: Basic $AUTH"
```

```powershell
# Windows
$auth = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('alice:<password>'))
claude mcp add --transport http mongo https://mongo-mcp.example.com/mcp --header "Authorization: Basic $auth"
```

Custom connectors on claude.ai (web and desktop) cannot send a Basic header;
use Claude Code.

Every tool is read-only, so it is reasonable to allow them without prompting.
Add this to `.claude/settings.json`:

```json
{ "permissions": { "allow": ["mcp__mongo__*"] } }
```

## Audit log

Each tool call appends one JSON line to `/data/audit.jsonl`, in the `audit`
Docker volume. The line records the time, user, tool, connection, database,
collection, parameters, duration, result count, and whether the call was
rejected and why. Connection strings are scrubbed before anything is written.

```powershell
docker compose exec mcp tail -n 20 /data/audit.jsonl
```

## HTTP safeguards

- Only `/mcp` is public. `/healthz` exists for Docker only; Caddy returns 404 for it.
- Requests must arrive over HTTPS (`X-Forwarded-Proto`) and carry the configured Host.
- Browser requests (with an `Origin` header) are refused.
- After 10 failed logins in 5 minutes, that IP gets 429 for 15 minutes.
- Passwords are at least 16 characters and stored as scrypt hashes.
- Request bodies are limited to 1 MiB.

## Development

```bash
npm ci --legacy-peer-deps
npm run typecheck
npm test     # the end-to-end suite runs against mongod on 127.0.0.1:27017 and skips itself if none is running
```

See `CLAUDE.md` for the rules any change must keep.
