import { DatabaseSync } from 'node:sqlite';
import { MIGRATIONS, migrate, openDatabase, transaction } from '../db';
import { tmpDir } from './helpers';

describe('SQLite persistence', () => {
  test('migrations create all tables and are idempotent', () => {
    const dir = tmpDir();
    const db = openDatabase(dir);
    const tables = (db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all() as { name: string }[]).map((r) => r.name);
    for (const t of ['users', 'webauthn_credentials', 'sessions', 'webauthn_challenges', 'approval_requests', 'approval_decisions',
      'decision_requests', 'decision_answers', 'audit_log', 'signing_keys', 'schema_migrations', 'meta']) {
      expect(tables).toContain(t);
    }
    expect(migrate(db)).toEqual([]);
    const versions = (db.prepare('SELECT version FROM schema_migrations').all() as { version: number }[]).map((r) => r.version);
    expect(versions).toEqual(MIGRATIONS.map((m) => m.version));
    db.close();
    const again = openDatabase(dir);
    expect((again.prepare('SELECT COUNT(*) n FROM schema_migrations').get() as { n: number }).n).toBe(MIGRATIONS.length);
    again.close();
  });

  test('migration 2 upgrades a v1 database in place (decision package binding columns)', () => {
    const dir = tmpDir();
    const raw = new DatabaseSync(`${dir}/idp.sqlite`);
    raw.exec('CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL)');
    raw.exec(MIGRATIONS[0].sql);
    raw.prepare('INSERT INTO schema_migrations VALUES (1, ?, 0)').run(MIGRATIONS[0].name);
    raw.close();
    const db = openDatabase(dir);
    const cols = (db.prepare('PRAGMA table_info(decision_requests)').all() as { name: string }[]).map((c) => c.name);
    expect(cols).toEqual(expect.arrayContaining(['package_id', 'revision', 'operation']));
    expect((db.prepare('SELECT MAX(version) v FROM schema_migrations').get() as { v: number }).v).toBe(MIGRATIONS.length);
    db.close();
  });

  test('data survives reopening (real file, not memory)', () => {
    const dir = tmpDir();
    const db = openDatabase(dir);
    db.prepare("INSERT INTO meta (key, value) VALUES ('k', 'v')").run();
    db.close();
    const db2 = new DatabaseSync(`${dir}/idp.sqlite`);
    expect((db2.prepare("SELECT value FROM meta WHERE key='k'").get() as { value: string }).value).toBe('v');
    db2.close();
  });

  test('transaction commits atomically and rolls back everything on error', () => {
    const db = openDatabase(tmpDir());
    transaction(db, () => {
      db.prepare("INSERT INTO meta VALUES ('a', '1')").run();
      transaction(db, () => db.prepare("INSERT INTO meta VALUES ('b', '2')").run());
    });
    expect(() =>
      transaction(db, () => {
        db.prepare("INSERT INTO meta VALUES ('c', '3')").run();
        transaction(db, () => db.prepare("INSERT INTO meta VALUES ('d', '4')").run());
        throw new Error('boom');
      }),
    ).toThrow('boom');
    const keys = (db.prepare('SELECT key FROM meta ORDER BY key').all() as { key: string }[]).map((r) => r.key);
    expect(keys).toEqual(['a', 'b']);
    // a failed transaction leaves the connection usable
    transaction(db, () => db.prepare("INSERT INTO meta VALUES ('e', '5')").run());
    expect((db.prepare('SELECT COUNT(*) n FROM meta').get() as { n: number }).n).toBe(3);
    db.close();
  });

  test('async callbacks are refused (would break atomicity)', () => {
    const db = openDatabase(tmpDir());
    expect(() => transaction(db, (async () => 1) as never)).toThrow(/synchronous/);
    db.close();
  });

  test('schema enforces state values and uniqueness', () => {
    const db = openDatabase(tmpDir());
    const ins = db.prepare(`INSERT INTO approval_requests VALUES (?, 'p', 'k', 1, 'c', 's', NULL, NULL, 'op', ?, '""', 1, 2, 1, ?)`);
    ins.run('r1', 'nonce-aaaaaaaaaaaaaaaa', 'PENDING');
    expect(() => ins.run('r2', 'nonce-aaaaaaaaaaaaaaaa', 'PENDING')).toThrow();
    expect(() => ins.run('r3', 'nonce-bbbbbbbbbbbbbbbb', 'WHATEVER')).toThrow();
    db.close();
  });
});
