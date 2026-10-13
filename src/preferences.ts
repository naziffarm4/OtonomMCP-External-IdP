/**
 * Cross-project user preferences ("Director memory"). OtonomMCP pushes preferences learned from
 * past clarification/design answers (bearer) and pulls the list at run start; the Product Owner
 * views, edits and deletes them in the UI (session + CSRF). Deleted ids are tombstoned so a
 * client that still has them locally never re-adds them. Informational: grants no authority.
 */
import * as crypto from 'node:crypto';
import type { IdpConfig } from './config';
import { audit, transaction, type Db } from './db';
import * as v from './validation';
import { HttpError } from './validation';

export const MAX_PREFERENCES = 200;
export const MAX_TOPIC = 200;
export const MAX_TEXT = 1000;
const ID_RE = /^[A-Za-z0-9._:-]{1,80}$/;
const SOURCES = ['clarification', 'design', 'note', 'ui'] as const;

export interface Preference { id: string; topic: string; text: string; source: string; project: string | null; createdAt: string; updatedAt: string }

interface Row { id: string; topic: string; text: string; source: string; project: string | null; created_at: number; updated_at: number }
const toPref = (r: Row): Preference => ({ id: r.id, topic: r.topic, text: r.text, source: r.source, project: r.project, createdAt: new Date(r.created_at).toISOString(), updatedAt: new Date(r.updated_at).toISOString() });

function clean(s: unknown, max: number, what: string): string {
  if (typeof s !== 'string') throw v.bad(`${what} must be a string`);
  // eslint-disable-next-line no-control-regex
  const t = s.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim();
  if (!t) throw v.bad(`${what} must not be empty`);
  return t.slice(0, max);
}

export class PreferenceService {
  constructor(private readonly db: Db, private readonly cfg: IdpConfig) {}

  list(): { items: Preference[]; deletedIds: string[] } {
    const items = (this.db.prepare('SELECT * FROM preferences ORDER BY updated_at DESC').all() as unknown as Row[]).map(toPref);
    const deletedIds = (this.db.prepare('SELECT id FROM preference_tombstones ORDER BY deleted_at DESC LIMIT 1000').all() as { id: string }[]).map((r) => r.id);
    return { items, deletedIds };
  }

  /** Machine push: adds unknown ids only (UI edits win; tombstoned ids are ignored). */
  push(body: unknown): { added: number; items: Preference[]; deletedIds: string[] } {
    const o = v.asObject(body);
    v.rejectUnknownKeys(o, ['items']);
    if (!Array.isArray(o.items) || o.items.length > MAX_PREFERENCES) throw v.bad(`items must be an array of at most ${MAX_PREFERENCES}`);
    const now = this.cfg.now();
    let added = 0;
    transaction(this.db, () => {
      for (const raw of o.items as unknown[]) {
        const it = v.asObject(raw, 'item');
        const id = typeof it.id === 'string' && ID_RE.test(it.id) ? it.id : null;
        if (!id) throw v.bad('item.id must be 1-80 chars [A-Za-z0-9._:-]');
        if (this.db.prepare('SELECT 1 FROM preference_tombstones WHERE id = ?').get(id)) continue;
        if (this.db.prepare('SELECT 1 FROM preferences WHERE id = ?').get(id)) continue;
        if (this.count() >= MAX_PREFERENCES) break;
        const source = typeof it.source === 'string' && (SOURCES as readonly string[]).includes(it.source) ? it.source : 'note';
        const project = typeof it.project === 'string' ? it.project.slice(0, 200) : null;
        this.db.prepare('INSERT INTO preferences (id, topic, text, source, project, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
          id, clean(it.topic, MAX_TOPIC, 'topic'), clean(it.text, MAX_TEXT, 'text'), source, project, now, now);
        added++;
      }
    });
    if (added) audit(this.db, now, 'client', 'PREFERENCES_PUSHED', null, { added });
    return { added, ...this.list() };
  }

  private count(): number {
    return (this.db.prepare('SELECT COUNT(*) AS n FROM preferences').get() as { n: number }).n;
  }

  create(body: unknown, userId: string): Preference {
    const o = v.asObject(body);
    v.rejectUnknownKeys(o, ['topic', 'text']);
    if (this.count() >= MAX_PREFERENCES) throw new HttpError(409, 'TOO_MANY', `At most ${MAX_PREFERENCES} preferences`);
    const now = this.cfg.now();
    const id = `u-${crypto.randomBytes(6).toString('hex')}`;
    this.db.prepare('INSERT INTO preferences (id, topic, text, source, project, created_at, updated_at) VALUES (?, ?, ?, ?, NULL, ?, ?)').run(
      id, clean(o.topic, MAX_TOPIC, 'topic'), clean(o.text, MAX_TEXT, 'text'), 'ui', now, now);
    audit(this.db, now, userId, 'PREFERENCE_CREATED', id);
    return toPref(this.db.prepare('SELECT * FROM preferences WHERE id = ?').get(id) as unknown as Row);
  }

  update(id: string, body: unknown, userId: string): Preference {
    if (!ID_RE.test(id)) throw v.bad('invalid id');
    const o = v.asObject(body);
    v.rejectUnknownKeys(o, ['topic', 'text']);
    const now = this.cfg.now();
    const r = this.db.prepare('UPDATE preferences SET topic = ?, text = ?, updated_at = ? WHERE id = ?').run(clean(o.topic, MAX_TOPIC, 'topic'), clean(o.text, MAX_TEXT, 'text'), now, id);
    if (!r.changes) throw new HttpError(404, 'NOT_FOUND', 'Preference not found');
    audit(this.db, now, userId, 'PREFERENCE_UPDATED', id);
    return toPref(this.db.prepare('SELECT * FROM preferences WHERE id = ?').get(id) as unknown as Row);
  }

  remove(id: string, userId: string): { ok: true } {
    if (!ID_RE.test(id)) throw v.bad('invalid id');
    const now = this.cfg.now();
    transaction(this.db, () => {
      const r = this.db.prepare('DELETE FROM preferences WHERE id = ?').run(id);
      if (!r.changes) throw new HttpError(404, 'NOT_FOUND', 'Preference not found');
      this.db.prepare('INSERT OR REPLACE INTO preference_tombstones (id, deleted_at) VALUES (?, ?)').run(id, now);
    });
    audit(this.db, now, userId, 'PREFERENCE_DELETED', id);
    return { ok: true };
  }
}
