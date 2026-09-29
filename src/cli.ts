#!/usr/bin/env node
/**
 * Entry point: `node dist/cli.js` (the Docker image runs this).
 *
 *   mongo-mcp                          MCP server over Streamable HTTP at http://<host>:8765/mcp
 *          [--host H] [--port N]         bind address / port (env: MONGO_MCP_HTTP_HOST, MONGO_MCP_HTTP_PORT)
 *   mongo-mcp --check                  validate config, probe each connection, print a safe summary
 *   mongo-mcp --hash-password USER     read a password from stdin, print a users.json entry
 *   mongo-mcp --config PATH            use a specific connections.json
 *   mongo-mcp --env-file PATH          load a specific .env
 *
 * Environment: MONGO_MCP_USERS_FILE (accounts), MONGO_MCP_HTTP_ALLOWED_HOSTS,
 * MONGO_MCP_HTTP_ALLOWED_ORIGINS (comma-separated), MONGO_MCP_TRUST_PROXY=1 when
 * a TLS proxy sits in front. All diagnostics go to stderr.
 */
import { defaultAuditLogPath, defaultUsersFilePath, loadEnvFiles, loadRegistry } from './config.js';
import { Authenticator, MIN_PASSWORD_LENGTH, hashPassword, loadUsersFile } from './auth.js';
import { DEFAULT_HTTP_HOST, DEFAULT_HTTP_PORT, startHttpServer } from './http.js';
import { ClientManager } from './mongodb/client.js';
import { describeConnection } from './mongodb/connections.js';
import { Redactor } from './security/redact.js';
import { createContext } from './server.js';

interface CliArgs {
  check: boolean;
  hashPassword?: string;
  host?: string;
  port?: number;
  config?: string;
  envFile?: string;
  help: boolean;
}

function parseArgs(argv: string[]): CliArgs {
  const out: CliArgs = { check: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    const next = (): string | undefined => argv[++i];
    if (a === '--check') out.check = true;
    else if (a === '--hash-password') out.hashPassword = next();
    else if (a === '--help' || a === '-h') out.help = true;
    else if (a === '--config') out.config = next();
    else if (a === '--env-file') out.envFile = next();
    else if (a === '--host') out.host = next();
    else if (a === '--port') out.port = Number(next());
    else if (a.startsWith('--config=')) out.config = a.slice(9);
    else if (a.startsWith('--env-file=')) out.envFile = a.slice(11);
    else if (a.startsWith('--host=')) out.host = a.slice(7);
    else if (a.startsWith('--port=')) out.port = Number(a.slice(7));
    else {
      process.stderr.write(`[mongo-mcp] unknown argument: ${a}\n`);
      out.help = true;
    }
  }
  return out;
}

const log = (msg: string): boolean => process.stderr.write(`[mongo-mcp] ${msg}\n`);

const USAGE = `usage: mongo-mcp [--host H] [--port N] [--check] [--hash-password USER] [--config PATH] [--env-file PATH]\n`;

/** Reads one line from stdin without echoing it when stdin is a terminal. */
async function readSecret(prompt: string): Promise<string> {
  const stdin = process.stdin;
  if (!stdin.isTTY) {
    let data = '';
    for await (const chunk of stdin) data += String(chunk);
    return data.replace(/\r?\n$/, '');
  }
  process.stderr.write(prompt);
  stdin.setRawMode(true);
  stdin.resume();
  return new Promise((resolve, reject) => {
    let value = '';
    const onData = (buf: Buffer): void => {
      for (const ch of buf.toString('utf8')) {
        if (ch === '\r' || ch === '\n') {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.off('data', onData);
          process.stderr.write('\n');
          return resolve(value);
        }
        if (ch === '\u0003') {
          stdin.setRawMode(false);
          return reject(new Error('cancelled'));
        }
        if (ch === '\u007f') value = value.slice(0, -1);
        else value += ch;
      }
    };
    stdin.on('data', onData);
  });
}

async function printPasswordHash(username: string | undefined): Promise<number> {
  if (!username || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(username)) {
    log('--hash-password needs a username: lowercase letters, digits, . _ -');
    return 2;
  }
  const password = await readSecret(`password for ${username} (min ${MIN_PASSWORD_LENGTH} chars): `);
  const hash = hashPassword(password);
  process.stdout.write(`${JSON.stringify(username)}: ${JSON.stringify(hash)}\n`);
  log('add that line to users.json and restart the server');
  return 0;
}

async function check(configPath: string | undefined): Promise<number> {
  const { registry, configPath: used } = loadRegistry(configPath);
  const clients = new ClientManager({ serverSelectionTimeoutMS: 5_000 });
  const redactor = new Redactor(clients.secretValues(registry.all()));
  log(`config: ${used}`);
  log(`audit log: ${defaultAuditLogPath()}`);
  let failures = 0;
  try {
    const users = loadUsersFile(defaultUsersFilePath());
    log(`users: ${Object.keys(users).length} account(s) in ${defaultUsersFilePath()}`);
  } catch (err) {
    log(`✗ users: ${(err as Error).message}`);
    failures++;
  }
  for (const conn of registry.all()) {
    const summary = describeConnection(conn);
    const head = `${conn.name}${conn.production ? ' [PRODUCTION]' : ''}`;
    if (!summary.credentialsConfigured) {
      log(`✗ ${head}: env var ${conn.uriEnv} not set`);
      failures++;
      continue;
    }
    const started = performance.now();
    try {
      const hello = await clients.hello(conn);
      const ms = Math.round(performance.now() - started);
      log(
        `✓ ${head}: connected in ${ms} ms (${hello.setName ? `replica set ${hello.setName}` : 'standalone'}, maxWireVersion ${hello.maxWireVersion}); ` +
          `databases: ${summary.allowedDatabases.join(', ')}; collections: ${Array.isArray(summary.allowedCollections) ? summary.allowedCollections.join(', ') : '*'}; ` +
          `limit ${conn.defaultLimit}/${conn.maxLimit}, maxTimeMS ${conn.maxTimeMS}, rejectCollscan ${conn.rejectCollscan}`,
      );
    } catch (err) {
      log(`✗ ${head}: ${redactor.error(err)}`);
      failures++;
    }
  }
  await clients.closeAll();
  return failures ? 1 : 0;
}

const envList = (name: string): string[] | undefined =>
  process.env[name]
    ?.split(',')
    .map((s) => s.trim())
    .filter(Boolean);

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    process.stderr.write(USAGE);
    process.exit(2);
  }
  if (args.hashPassword !== undefined || process.argv.includes('--hash-password')) process.exit(await printPasswordHash(args.hashPassword));

  const envFiles = loadEnvFiles(args.envFile);
  if (envFiles.length) log(`loaded env from ${envFiles.join(', ')}`);

  if (args.check) process.exit(await check(args.config));

  const { registry, configPath } = loadRegistry(args.config);
  const auth = new Authenticator(loadUsersFile(defaultUsersFilePath()));
  const echoAudit = process.env.MONGO_MCP_DEBUG === '1';
  const { ctx, close } = createContext({ registry, auditLogPath: defaultAuditLogPath(), echoAuditToStderr: echoAudit });
  const host = args.host ?? process.env.MONGO_MCP_HTTP_HOST ?? DEFAULT_HTTP_HOST;
  const port = args.port ?? Number(process.env.MONGO_MCP_HTTP_PORT ?? DEFAULT_HTTP_PORT);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error(`invalid port: ${port}`);
  const trustProxy = process.env.MONGO_MCP_TRUST_PROXY === '1';

  const running = await startHttpServer({
    ctx,
    host,
    port,
    auth,
    trustProxy,
    allowedHosts: envList('MONGO_MCP_HTTP_ALLOWED_HOSTS'),
    allowedOrigins: envList('MONGO_MCP_HTTP_ALLOWED_ORIGINS'),
    log,
  });
  log(`listening on ${running.url} (bound to ${host}:${running.port}; config ${configPath}; ${auth.size} user(s); connections: ${registry.names().join(', ')})`);
  if (!trustProxy && host !== '127.0.0.1' && host !== 'localhost' && host !== '::1') {
    log('warning: bound to a non-loopback address without MONGO_MCP_TRUST_PROXY=1; passwords would travel without TLS unless a proxy terminates it');
  }

  const shutdown = async (why: string): Promise<void> => {
    log(`shutting down (${why})`);
    await running.close();
    await close();
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  process.stderr.write(`[mongo-mcp] fatal: ${msg.replace(/mongodb(\+srv)?:\/\/\S+/gi, '[REDACTED]')}\n`);
  process.exit(1);
});
