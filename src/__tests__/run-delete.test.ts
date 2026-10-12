import { SoftAuthenticator } from '../testing/soft-authenticator';
import { enroll, startHarness, type Harness } from './helpers';
import { ev, snapshot } from './runs.test';

function channel(runId: string) {
  return { runId, projectId: 'LLMTEST', packageId: 'pkg-autonomous-abc-123', revision: 1, contextFingerprint: 'a'.repeat(64), openedAt: new Date().toISOString() };
}
const auditCount = (h: Harness, runId: string) =>
  (h.idp.db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event = 'run.deleted' AND target_id = ?").get(runId) as { n: number }).n;
const count = (h: Harness, table: string, runId: string) =>
  (h.idp.db.prepare(`SELECT COUNT(*) n FROM ${table} WHERE run_id = ?`).get(runId) as { n: number }).n;

describe('run delete (UI)', () => {
  let h: Harness;
  beforeEach(async () => { h = await startHarness(); });
  afterEach(async () => { await h.close(); });

  test('terminal run: deleted with events, channel and instructions; audited; 404 afterwards', async () => {
    const { browser, auth } = await enroll(h);
    h.idp.runs.putSnapshot('r-run', snapshot({ runId: 'r-run' }));
    h.idp.runs.appendEvents('r-run', { events: [ev(1), ev(2)] });
    expect((await h.bearer('PUT', '/api/runs/r-run/instruction-channel', channel('r-run'))).status).toBe(200);
    const o = await browser.req('POST', '/api/ui/runs/r-run/instructions/options', { mode: 'NOTE', text: 'not' });
    expect((await browser.req('POST', `/api/ui/runs/r-run/instructions/${o.json.instructionId}`, { assertion: (auth as SoftAuthenticator).authenticate(o.json.options) })).status).toBe(200);
    h.idp.runs.putSnapshot('r-run', snapshot({ runId: 'r-run', seq: 2, status: 'COMPLETED' }));
    const list = await browser.req('GET', '/api/ui/runs');
    expect(list.json.runs[0]).toMatchObject({ runId: 'r-run', deletable: true, stale: false });
    const r = await browser.req('DELETE', '/api/ui/runs/r-run');
    expect(r.status).toBe(200);
    expect(r.json).toEqual({ ok: true, runId: 'r-run', deleted: { events: 2, instructions: 1 } });
    expect(count(h, 'runs', 'r-run')).toBe(0);
    expect(count(h, 'run_events', 'r-run')).toBe(0);
    expect(count(h, 'instruction_channels', 'r-run')).toBe(0);
    expect(count(h, 'instructions', 'r-run')).toBe(0);
    expect((await h.bearer('GET', '/api/runs/r-run/instructions')).json.instructions).toEqual([]);
    expect(auditCount(h, 'r-run')).toBe(1);
    expect((await browser.req('GET', '/api/ui/runs/r-run')).status).toBe(404);
    expect((await browser.req('DELETE', '/api/ui/runs/r-run')).status).toBe(404);
  });

  test('live run -> 409 RUN_ACTIVE; becomes deletable once stale (default 15 min, by IdP receive time)', async () => {
    const { browser } = await enroll(h);
    h.idp.runs.putSnapshot('r-live', snapshot({ runId: 'r-live' }));
    const r = await browser.req('DELETE', '/api/ui/runs/r-live');
    expect(r.status).toBe(409);
    expect(r.json.error).toBe('RUN_ACTIVE');
    expect(r.json.message).toContain('15 dakika');
    expect((await browser.req('GET', '/api/ui/runs')).json.runs[0]).toMatchObject({ deletable: false, stale: false });
    h.clock.now += 14 * 60_000;
    h.idp.runs.appendEvents('r-live', { events: [ev(1)] }); // an event refreshes liveness
    h.clock.now += 14 * 60_000;
    expect((await browser.req('DELETE', '/api/ui/runs/r-live')).status).toBe(409);
    h.clock.now += 2 * 60_000;
    expect((await browser.req('GET', '/api/ui/runs')).json.runs[0]).toMatchObject({ deletable: true, stale: true });
    expect((await browser.req('DELETE', '/api/ui/runs/r-live')).status).toBe(200);
  });

  test('IDP_RUN_STALE_MINUTES configures staleness', async () => {
    await h.close();
    h = await startHarness({ env: { IDP_RUN_STALE_MINUTES: '2' } });
    const { browser } = await enroll(h);
    h.idp.runs.putSnapshot('r', snapshot({ runId: 'r' }));
    h.clock.now += 3 * 60_000;
    expect((await browser.req('DELETE', '/api/ui/runs/r')).status).toBe(200);
  });

  test('auth: session + same origin + CSRF required; bearer token is not enough', async () => {
    h.idp.runs.putSnapshot('r', snapshot({ runId: 'r', status: 'FAILED' }));
    expect((await h.bearer('DELETE', '/api/ui/runs/r')).status).toBe(401);
    const anon = h.browser();
    expect((await anon.req('DELETE', '/api/ui/runs/r')).status).toBe(401);
    const { browser } = await enroll(h);
    expect((await browser.req('DELETE', '/api/ui/runs/r', undefined, { 'X-CSRF-Token': 'wrong' })).status).toBe(403);
    expect((await browser.req('DELETE', '/api/ui/runs/r', undefined, { Origin: 'http://evil.example' })).status).toBe(403);
    expect((await browser.req('DELETE', '/api/ui/runs/r', undefined, { 'Sec-Fetch-Site': 'cross-site' })).status).toBe(403);
    expect((await browser.req('POST', '/api/ui/runs/cleanup', {}, { 'X-CSRF-Token': 'wrong' })).status).toBe(403);
    expect((await browser.req('DELETE', '/api/ui/runs/bad%20id')).status).toBe(400);
    expect(count(h, 'runs', 'r')).toBe(1);
  });

  test('bulk cleanup deletes only terminal/stale runs', async () => {
    const { browser } = await enroll(h);
    h.idp.runs.putSnapshot('old', snapshot({ runId: 'old' }));
    h.clock.now += 20 * 60_000;
    h.idp.runs.putSnapshot('live', snapshot({ runId: 'live' }));
    h.idp.runs.putSnapshot('done', snapshot({ runId: 'done', status: 'STOPPED' }));
    const r = await browser.req('POST', '/api/ui/runs/cleanup', {});
    expect(r.status).toBe(200);
    expect(r.json.deleted.sort()).toEqual(['done', 'old']);
    expect((await browser.req('GET', '/api/ui/runs')).json.runs.map((x: any) => x.runId)).toEqual(['live']);
  });

  test('OtonomMCP writing to a deleted runId simply recreates it (snapshot any seq, or events-only row)', async () => {
    const { browser } = await enroll(h);
    h.idp.runs.putSnapshot('r', snapshot({ runId: 'r', seq: 9, status: 'FAILED' }));
    expect((await browser.req('DELETE', '/api/ui/runs/r')).status).toBe(200);
    expect((await h.bearer('PUT', '/api/runs/r', snapshot({ runId: 'r', seq: 3 }))).json).toEqual({ runId: 'r', stored: true });
    expect(h.idp.runs.detail('r', null).run.status).toBe('RUNNING');
    expect((await browser.req('DELETE', '/api/ui/runs/r')).status).toBe(409);
    h.idp.runs.putSnapshot('e', snapshot({ runId: 'e', status: 'COMPLETED' }));
    expect((await browser.req('DELETE', '/api/ui/runs/e')).status).toBe(200);
    expect((await h.bearer('POST', '/api/runs/e/events', { events: [ev(5)] })).json.accepted).toBe(1);
    expect((await h.bearer('DELETE', '/api/runs/r/instruction-channel')).status).toBe(404);
  });
});
