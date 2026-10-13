import * as path from 'node:path';
import { startHarness, enroll, type Harness } from './helpers';

describe('cross-project preferences (Director memory)', () => {
  let h: Harness;
  beforeEach(async () => { h = await startHarness(); });
  afterEach(async () => { await h.close(); });

  test('machine push/pull; UI edit wins; delete tombstones; auth + CSRF', async () => {
    expect((await h.bearer('GET', '/api/preferences', undefined, '')).status).toBe(401);
    const p1 = await h.bearer('PUT', '/api/preferences', { items: [{ id: 'clar-renk', topic: 'Renkler', text: 'Pembe yok', source: 'clarification', project: 'kuafor' }] });
    expect(p1.status).toBe(200);
    expect(p1.json.added).toBe(1);
    expect((await h.bearer('PUT', '/api/preferences', { items: [{ id: 'bad id!', topic: 't', text: 'x' }] })).status).toBe(400);
    const { browser } = await enroll(h);
    const list = await browser.req('GET', '/api/ui/preferences');
    expect(list.json.items[0]).toMatchObject({ id: 'clar-renk', topic: 'Renkler', source: 'clarification' });
    expect((await browser.req('PUT', '/api/ui/preferences/clar-renk', { topic: 'Renkler', text: 'Pembe ve mor yok' })).status).toBe(200);
    // a later machine push with the same id never overwrites the PO's edit
    await h.bearer('PUT', '/api/preferences', { items: [{ id: 'clar-renk', topic: 'Renkler', text: 'Pembe yok' }] });
    expect((await h.bearer('GET', '/api/preferences')).json.items[0].text).toBe('Pembe ve mor yok');
    const add = await browser.req('POST', '/api/ui/preferences', { topic: 'Yazı', text: 'Büyük, okunaklı' });
    expect(add.status).toBe(200);
    expect(add.json.source).toBe('ui');
    expect((await browser.req('DELETE', '/api/ui/preferences/clar-renk')).status).toBe(200);
    const after = (await h.bearer('GET', '/api/preferences')).json;
    expect(after.items.map((i: any) => i.id)).toEqual([add.json.id]);
    expect(after.deletedIds).toContain('clar-renk');
    // tombstoned id is not re-added by the client
    expect((await h.bearer('PUT', '/api/preferences', { items: [{ id: 'clar-renk', topic: 'Renkler', text: 'Pembe yok' }] })).json.added).toBe(0);
    // CSRF: a mutating UI call without the token is refused
    const res = await fetch(h.base + '/api/ui/preferences', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'http://localhost:7443' }, body: JSON.stringify({ topic: 'a', text: 'b' }) });
    expect([401, 403]).toContain(res.status);
  });

  test('progress notes are accepted as run events', async () => {
    expect((await h.bearer('POST', '/api/runs/r1/events', { events: [{ seq: 1, at: new Date().toISOString(), type: 'PROGRESS_NOTE', level: 'info', taskId: null, message: 'Ne oldu: ...' }, { seq: 2, at: new Date().toISOString(), type: 'DECISION_LOG', level: 'info', taskId: 'T1', message: '[Plan] x — ' + 'g'.repeat(650) }] })).status).toBe(200);
  });

  test('UI renders preferences and progress notes as text', () => {
    (globalThis as any).__IDP_TEST__ = true;
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const ui = require(path.resolve(__dirname, '..', '..', 'public', 'app.js'));
    const mk = (t: string): any => { const n: any = { nodeType: 1, tagName: t, children: [], appendChild(c: any) { n.children.push(c); return c; }, addEventListener() {}, setAttribute() {} }; return n; };
    const doc = { createElement: mk, createTextNode: (s: string) => ({ nodeType: 3, data: s, children: [] }) };
    const text = (n: any): string => (n.nodeType === 3 ? n.data : (n.children || []).map(text).join(''));
    const node = ui.renderPreferences(doc, { items: [{ id: 'a', topic: '<b>Renk</b>', text: 'Pembe yok', source: 'design', project: 'p', updatedAt: new Date().toISOString() }] }, { save() {}, remove() {}, add() {} });
    expect(text(node)).toContain('tasarım seçimi');
  });
});
