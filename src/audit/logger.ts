/**
 * Append-only JSONL audit log of every tool invocation, successful or not.
 * All strings pass through the Redactor so URIs and credentials can never land on disk.
 */
import fs from 'node:fs';
import path from 'node:path';
import type { AuditRecord } from '../types.js';
import { Redactor } from '../security/redact.js';

const MAX_PARAMS_CHARS = 8_000;

export interface AuditLoggerOptions {
  filePath: string | null;
  redactor: Redactor;
  echoToStderr?: boolean;
}

export class AuditLogger {
  private readonly filePath: string | null;
  private readonly redactor: Redactor;
  private readonly echo: boolean;
  private ready = false;

  constructor(opts: AuditLoggerOptions) {
    this.filePath = opts.filePath;
    this.redactor = opts.redactor;
    this.echo = opts.echoToStderr ?? false;
  }

  get path(): string | null {
    return this.filePath;
  }

  log(record: AuditRecord): void {
    const safe = this.redactor.deep(record);
    let line = JSON.stringify(safe);
    if (line.length > MAX_PARAMS_CHARS * 2) {
      // Keep the log bounded: truncate params, never the outcome fields.
      const truncated = { ...safe, params: JSON.stringify(safe.params).slice(0, MAX_PARAMS_CHARS) + '…[truncated]' };
      line = JSON.stringify(truncated);
    }
    if (this.filePath) {
      try {
        if (!this.ready) {
          fs.mkdirSync(path.dirname(this.filePath), { recursive: true, mode: 0o700 });
          this.ready = true;
        }
        fs.appendFileSync(this.filePath, line + '\n', { mode: 0o600 });
      } catch (err) {
        process.stderr.write(`[mongo-mcp] audit write failed: ${this.redactor.error(err)}\n`);
      }
    }
    if (this.echo) process.stderr.write(`[mongo-mcp] ${line}\n`);
  }
}
