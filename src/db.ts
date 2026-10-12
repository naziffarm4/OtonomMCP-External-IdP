import * as fs from 'node:fs';
import * as path from 'node:path';
// node:sqlite ships with Node >= 22.5 (no native build step, works on Windows).
import { DatabaseSync } from 'node:sqlite';

export type Db = DatabaseSync;

interface Migration {
  version: number;
  name: string;
  sql: string;
}

/** Ordered, append-only schema migrations. Never edit an applied migration; add a new one. */
export const MIGRATIONS: readonly Migration[] = [
  {
    version: 1,
    name: 'initial schema',
    sql: `
      CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE users (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('PRODUCT_OWNER')),
        webauthn_user_id TEXT NOT NULL UNIQUE,
        created_at INTEGER NOT NULL,
        disabled INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE webauthn_credentials (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        public_key BLOB NOT NULL,
        counter INTEGER NOT NULL DEFAULT 0,
        transports TEXT,
        device_type TEXT,
        backed_up INTEGER NOT NULL DEFAULT 0,
        aaguid TEXT,
        created_at INTEGER NOT NULL,
        last_used_at INTEGER
      );
      CREATE INDEX idx_cred_user ON webauthn_credentials(user_id);
      CREATE TABLE sessions (
        id_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        csrf_token TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE TABLE webauthn_challenges (
        id TEXT PRIMARY KEY,
        challenge TEXT NOT NULL UNIQUE,
        purpose TEXT NOT NULL CHECK (purpose IN ('setup','register','login','approve','decide')),
        binding_hash TEXT NOT NULL,
        user_id TEXT,
        target_id TEXT,
        payload TEXT,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        used_at INTEGER
      );
      CREATE TABLE approval_requests (
        request_id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        package_id TEXT NOT NULL,
        revision INTEGER NOT NULL,
        context_fingerprint TEXT NOT NULL,
        spec_fingerprint TEXT NOT NULL,
        director_session_id TEXT,
        task_id TEXT,
        operation TEXT NOT NULL,
        nonce TEXT NOT NULL UNIQUE,
        summary TEXT NOT NULL,
        requested_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        received_at INTEGER NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('PENDING','APPROVED','REJECTED','EXPIRED'))
      );
      CREATE INDEX idx_req_status ON approval_requests(status);
      CREATE TABLE approval_decisions (
        request_id TEXT PRIMARY KEY REFERENCES approval_requests(request_id),
        decision TEXT NOT NULL CHECK (decision IN ('APPROVED','REJECTED')),
        user_id TEXT NOT NULL REFERENCES users(id),
        credential_id TEXT,
        reason TEXT,
        token TEXT,
        token_jti TEXT UNIQUE,
        token_expires_at INTEGER,
        decided_at INTEGER NOT NULL
      );
      CREATE TABLE decision_requests (
        decision_id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        run_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        context_fingerprint TEXT NOT NULL,
        question TEXT NOT NULL,
        options TEXT NOT NULL,
        allow_free_text INTEGER NOT NULL,
        recommended_option_id TEXT,
        nonce TEXT NOT NULL UNIQUE,
        summary TEXT,
        requested_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        received_at INTEGER NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('PENDING','ANSWERED','EXPIRED'))
      );
      CREATE INDEX idx_dec_status ON decision_requests(status);
      CREATE TABLE decision_answers (
        decision_id TEXT PRIMARY KEY REFERENCES decision_requests(decision_id),
        user_id TEXT NOT NULL REFERENCES users(id),
        credential_id TEXT NOT NULL,
        selected_option_id TEXT,
        free_text TEXT,
        token TEXT NOT NULL,
        token_jti TEXT NOT NULL UNIQUE,
        token_expires_at INTEGER NOT NULL,
        answered_at INTEGER NOT NULL
      );
      CREATE TABLE audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        at INTEGER NOT NULL,
        actor TEXT NOT NULL,
        event TEXT NOT NULL,
        target_id TEXT,
        details TEXT
      );
      CREATE TABLE signing_keys (
        kid TEXT PRIMARY KEY,
        alg TEXT NOT NULL,
        public_key_pem TEXT NOT NULL,
        private_key_file TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        active INTEGER NOT NULL DEFAULT 1
      );
    `,
  },
  {
    version: 2,
    name: 'decision requests carry approval package binding (contract v1.1)',
    sql: `
      ALTER TABLE decision_requests ADD COLUMN package_id TEXT;
      ALTER TABLE decision_requests ADD COLUMN revision INTEGER;
      ALTER TABLE decision_requests ADD COLUMN operation TEXT;
    `,
  },
];

export function openDatabase(dataDir: string, fileName = 'idp.sqlite'): Db {
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(path.join(dataDir, fileName));
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec('PRAGMA busy_timeout = 5000;');
  migrate(db);
  return db;
}

export function migrate(db: Db): number[] {
  db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL)`);
  const applied = new Set(
    (db.prepare('SELECT version FROM schema_migrations').all() as { version: number }[]).map((r) => r.version),
  );
  const ran: number[] = [];
  for (const m of MIGRATIONS) {
    if (applied.has(m.version)) continue;
    transaction(db, () => {
      db.exec(m.sql);
      db.prepare('INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)').run(m.version, m.name, Date.now());
    });
    ran.push(m.version);
  }
  return ran;
}

const txDepth = new WeakMap<Db, number>();

/**
 * Runs fn inside one IMMEDIATE transaction (write lock taken up front, so
 * check-then-write sequences are atomic). Nested calls join the outer one.
 * Any throw rolls back everything. fn must be synchronous.
 */
export function transaction<T>(db: Db, fn: () => T): T {
  const depth = txDepth.get(db) ?? 0;
  if (depth > 0) {
    txDepth.set(db, depth + 1);
    try {
      return fn();
    } finally {
      txDepth.set(db, depth);
    }
  }
  db.exec('BEGIN IMMEDIATE');
  txDepth.set(db, 1);
  try {
    const result = fn();
    if (result && typeof (result as { then?: unknown }).then === 'function') {
      throw new Error('transaction callback must be synchronous');
    }
    db.exec('COMMIT');
    return result;
  } catch (err) {
    try {
      db.exec('ROLLBACK');
    } catch {
      /* already rolled back */
    }
    throw err;
  } finally {
    txDepth.set(db, 0);
  }
}

export function audit(db: Db, at: number, actor: string, event: string, targetId?: string | null, details?: unknown): void {
  db.prepare('INSERT INTO audit_log (at, actor, event, target_id, details) VALUES (?, ?, ?, ?, ?)').run(
    at, actor, event, targetId ?? null, details === undefined ? null : JSON.stringify(details),
  );
}

export function getMeta(db: Db, key: string): string | undefined {
  const row = db.prepare('SELECT value FROM meta WHERE key = ?').get(key) as { value: string } | undefined;
  return row?.value;
}

export function setMeta(db: Db, key: string, value: string): void {
  db.prepare('INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(key, value);
}

export function deleteMeta(db: Db, key: string): void {
  db.prepare('DELETE FROM meta WHERE key = ?').run(key);
}
