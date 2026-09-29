# mongo-mcp — guidance for Claude Code sessions working on this repo

mongo-mcp is a **security boundary**. It runs on a VM with connection strings whose database
users may be able to write, and exposes read tools over HTTPS to Claude. Read-only rests on this
code, so treat every change accordingly.

## Non-negotiables

- **No write paths.** Never add a tool, option or code path that calls `insert*`, `update*`,
  `replace*`, `delete*`, `bulkWrite`, `drop*`, `rename*`, `createIndex*`, `runCommand`/`command`
  with user-controlled input, `$out`, `$merge`, or anything else that mutates data or schema.
  `command` is used in exactly three places (`listDatabases`, `hello` in `mongodb/client.ts`,
  `dbStats` in `mongodb/readonly.ts`) with hard-coded documents; keep it that way.
- **Tools only touch the read-only facades** (`mongodb/readonly.ts`). Never hand a tool the raw
  `MongoClient`, `Db` or `Collection`. Never widen `READ_COMMANDS` for anything that writes.
- **No generic escape hatch.** Never add `run_command`, `run_query`, `eval`, shell, or
  "raw pipeline without validation" tools. Every capability must be a specific, validated tool.
- **Allowlists over denylists.** New aggregation stages go on `ALLOWED_STAGES` only after
  confirming they are read-only and do not reveal cluster internals. Cross-collection stages must
  keep going through `assertCollectionRef`.
- **Security is enforced in code, not in prompts.** Descriptions/instructions help Claude behave;
  they are not a control. Every gate needs a test in `tests/`.
- **Secrets never leave the process.** URIs come from env vars named in config; they must not be
  logged, returned, or included in error messages. Everything Claude sees passes through
  `Redactor`. If you add a new output path, route it through `runTool` or the redactor.
- **Bounded by default.** Every read must have a `limit` (≤ `HARD_MAX_LIMIT`) and `maxTimeMS`
  (≤ `HARD_MAX_TIME_MS`). Server-side bounding (`$limit`, `.limit()`) beats client-side slicing.

## Layout

```
src/
  cli.ts                 HTTP server entry; --check probes connections; --hash-password makes accounts
  server.ts              createContext() shared state + tripwire; buildMcpServer() per request
  http.ts                Streamable HTTP: HTTPS/Host/Origin/lockout/Basic gates, stateless per-request servers
  auth.ts                scrypt password hashes, Basic parsing, failed-login limiter
  config.ts              locate/parse connections.json, users.json and .env / .env.sandbox / .env.production
  types.ts               shared types, ValidationError, AuditRecord
  security/
    allowlist.ts         connection/database/collection gates
    validator.ts         filter/pipeline/sort/hint structural validation, stage allowlist
    query-policy.ts      hard ceilings + per-connection resolution + limit clamping
    collscan.ts          pure explain-plan walker (COLLSCAN / indexes used)
    redact.ts            URI/credential scrubbing for logs and outputs
  mongodb/
    client.ts            lazy MongoClient per connection (private), command tripwire
    readonly.ts          read-only Db/Collection facades, READ_COMMANDS
    schema.ts            schema inference for collection-schema (types only, no values)
    inspect.ts           guardCollscan(): explain pre-flight + rejection
    connections.ts       safe connection summaries for Claude
  audit/logger.ts        JSONL audit log (redacted)
  tools/
    context.ts           runTool(): the single choke point (scope → body → audit → safe result)
    *.ts                 one file per tool group; index.ts = the closed EXPOSED_TOOLS list
tests/                   vitest; unit tests for the security layer + e2e against local mongod
config/                  *.example.json (committed) / connections.json, users.json (ignored)
Dockerfile, docker-compose.yml, deploy/Caddyfile   VM packaging: MCP container + Caddy for TLS
```

## Working on it

```bash
npm install --legacy-peer-deps   # npm 11 needs the flag for vitest's optional peers
npm run typecheck
npm test                         # e2e suite auto-skips if 127.0.0.1:27017 is unreachable
npx tsx src/cli.ts --check        # validates config and probes every connection (no secrets printed)
```

- Adding a tool: register it in `src/tools/`, add it to `EXPOSED_TOOLS`, route it through
  `runTool`, give it `READ_ONLY_ANNOTATIONS`, add e2e coverage, and update README's tool table
  and permission examples.
- Changing limits: only in `security/query-policy.ts`; add/adjust tests in
  `tests/query-policy.test.ts`.
- Never commit `.env`, `.env.sandbox`, `.env.production`, `config/connections.json`,
  `config/users.json` or audit logs (all git-ignored). Examples use placeholders only; never put a
  real or realistic connection string in the repo.
- HTTP: never weaken the HTTPS/Host/Origin/lockout/auth gates or bind to non-loopback by default
  outside Docker; every gate has a test in `tests/http.test.ts` or `tests/auth.test.ts`.
