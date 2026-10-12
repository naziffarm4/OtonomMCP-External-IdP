import * as crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { MAX_EVENTS_PER_RUN, MAX_RUNS } from '../runs';
import { ORIGIN, RP_ID, approvalBody, enroll, startHarness, tmpDir, type Harness } from './helpers';
import { SoftAuthenticator } from '../testing/soft-authenticator';

export function snapshot(over: Record<string, unknown> = {}) {
  const now = Date.now();
  return {
    runId: 'run-20261012-abc',
    seq: 1,
    projectId: 'LLMTEST',
    projectName: 'LLM Test Projesi',
    entryPoint: 'aidm_autonomous_start',
    status: 'RUNNING',
    startedAt: new Date(now - 60_000).toISOString(),
    updatedAt: new Date(now).toISOString(),
    finishedAt: null,
    model: 'gpt-6-luna',
    budget: { limitUsd: 3, committedUsd: 0.42, reservedUsd: 0.1 },
    currentTaskId: 'TASK-002',
    tasks: [
      { taskId: 'TASK-001', title: 'Ana sayfa', status: 'ACCEPTED', cycles: 1, maxAttempts: 3, lastSummary: 'index.html oluşturuldu' },
      { taskId: 'TASK-002', title: 'Hakkımda', status: 'IN_PROGRESS', cycles: 2, maxAttempts: 3, lastSummary: null },
    ],
    lastDirectorAction: { actionType: 'IMPLEMENT_TASK', taskId: 'TASK-002', rationale: 'Sıradaki görev', at: new Date(now).toISOString() },
    pendingApprovalId: null,
    pendingDecisionIds: [],
    stopReason: null,
    ...over,
  };
}
export function ev(seq: number, over: Record<string, unknown> = {}) {
  return { seq, at: new Date().toISOString(), type: 'CYCLE_START', level: 'info', taskId: 'TASK-002', message: `olay ${seq}`, ...over };
}

describe('run monitor machine API', () => {
  let h: Harness;
  beforeEach(async () => { h = await startHarness(); });
  afterEach(async () => { await h.close(); });
  const put = (body: any, id = body.runId, tok?: string) => h.bearer('PUT', `/api/runs/${id}`, body, tok);
  const post = (id: string, events: unknown[], tok?: string) => h.bearer('POST', `/api/runs/${id}/events`, { events }, tok);

  test('snapshot upsert: stored, then seq <= stored ignored, higher seq wins', async () => {
    expect((await put(snapshot())).json).toEqual({ runId: 'run-20261012-abc', stored: true });
    expect((await put(snapshot({ seq: 1, status: 'FAILED' }))).json).toEqual({ runId: 'run-20261012-abc', ignored: true });
    expect((await put(snapshot({ seq: 0, status: 'FAILED' }))).json.ignored).toBe(true);
    expect((await put(snapshot({ seq: 5, status: 'COMPLETED', finishedAt: new Date().toISOString() }))).json.stored).toBe(true);
    const run = h.idp.runs.detail('run-20261012-abc', null).run;
    expect(run.status).toBe('COMPLETED');
    expect(run.snapshot!.seq).toBe(5);
  });

  test('auth: bearer required on both machine endpoints', async () => {
    expect((await put(snapshot(), undefined, '')).status).toBe(401);
    expect((await put(snapshot(), undefined, 'x'.repeat(40))).status).toBe(401);
    expect((await post('r1', [ev(1)], '')).status).toBe(401);
  });

  test.each([
    ['runId mismatch', { runId: 'other' }],
    ['unknown field', { secret: 'sk-123' }],
    ['bad status', { status: 'DONE' }],
    ['bad entryPoint', { entryPoint: 'cli' }],
    ['negative seq', { seq: -1 }],
    ['float seq', { seq: 1.5 }],
    ['negative budget', { budget: { limitUsd: -1, committedUsd: 0, reservedUsd: 0 } }],
    ['unknown budget field', { budget: { limitUsd: 1, committedUsd: 0, reservedUsd: 0, apiKey: 'x' } }],
    ['too many tasks', { tasks: Array.from({ length: 101 }, (_, i) => ({ taskId: `T${i}`, title: 't', status: 's', cycles: 0 })) }],
    ['task title too long', { tasks: [{ taskId: 'T', title: 'x'.repeat(201), status: 's', cycles: 0 }] }],
    ['task unknown field', { tasks: [{ taskId: 'T', title: 't', status: 's', cycles: 0, output: 'full agy output' }] }],
    ['lastSummary too long', { tasks: [{ taskId: 'T', title: 't', status: 's', cycles: 0, lastSummary: 'x'.repeat(501) }] }],
    ['rationale too long', { lastDirectorAction: { actionType: 'X', rationale: 'x'.repeat(1001), at: new Date().toISOString() } }],
    ['pendingApprovalId not uuid', { pendingApprovalId: 'abc' }],
    ['pendingDecisionIds not array', { pendingDecisionIds: null }],
    ['too many decision ids', { pendingDecisionIds: Array.from({ length: 21 }, () => crypto.randomUUID()) }],
    ['bad updatedAt', { updatedAt: 'now' }],
    ['missing projectName', { projectName: undefined }],
    ['control chars', { projectName: 'a\u0000b' }],
    ['stopReason too long', { stopReason: 'x'.repeat(1001) }],
  ])('snapshot validation: %s -> 400', async (_n, over) => {
    const body: any = snapshot(over as any);
    for (const k of Object.keys(body)) if (body[k] === undefined) delete body[k];
    const r = await put(body, 'run-20261012-abc');
    expect(r.status).toBe(400);
  });

  test('runId path charset is enforced', async () => {
    expect((await put(snapshot({ runId: 'a b' }), 'a%20b')).status).toBe(400);
    expect((await put(snapshot({ runId: 'x'.repeat(129) }), 'x'.repeat(129))).status).toBe(400);
    expect((await put(snapshot({ runId: 'run:1.a_b-c' }), 'run:1.a_b-c')).status).toBe(200);
    expect((await h.bearer('GET', '/api/runs/run-1')).status).toBe(405);
  });

  test('events: idempotent by (runId, seq), duplicates counted, ordered newest first', async () => {
    await put(snapshot());
    expect((await post('run-20261012-abc', [ev(1), ev(2), ev(3)])).json).toEqual({ runId: 'run-20261012-abc', accepted: 3, duplicates: 0 });
    expect((await post('run-20261012-abc', [ev(2), ev(3), ev(4)])).json).toEqual({ runId: 'run-20261012-abc', accepted: 1, duplicates: 2 });
    const d = h.idp.runs.detail('run-20261012-abc', null);
    expect(d.events.map((e) => e.seq)).toEqual([4, 3, 2, 1]);
    expect(d.lastSeq).toBe(4);
    expect(h.idp.runs.detail('run-20261012-abc', '2').events.map((e) => e.seq)).toEqual([4, 3]);
    // duplicate seq keeps the first message (no overwrite)
    await post('run-20261012-abc', [ev(1, { message: 'changed' })]);
    expect(h.idp.runs.detail('run-20261012-abc', null).events.find((e) => e.seq === 1)!.message).toBe('olay 1');
  });

  test.each([
    ['empty list', []],
    ['51 events', Array.from({ length: 51 }, (_, i) => ev(i))],
    ['bad type', [ev(1, { type: 'HACK' })]],
    ['bad level', [ev(1, { level: 'debug' })]],
    ['message too long', [ev(1, { message: 'x'.repeat(501) })]],
    ['empty message', [ev(1, { message: '' })]],
    ['unknown event field', [ev(1, { prompt: 'full prompt' })]],
    ['negative seq', [ev(-1)]],
  ])('events validation: %s -> 400', async (_n, events) => {
    expect((await post('run-1', events as unknown[])).status).toBe(400);
  });

  test('events body must be {events}; size limit 413', async () => {
    expect((await h.bearer('POST', '/api/runs/run-1/events', { events: [ev(1)], extra: 1 })).status).toBe(400);
    const big = Array.from({ length: 50 }, (_, i) => ev(i, { message: 'x'.repeat(500), taskId: 'y'.repeat(128) }));
    const r = await h.bearer('POST', '/api/runs/run-1/events', { events: big, pad: 'z'.repeat(40_000) });
    expect(r.status).toBe(413);
  });

  test('events for an unknown run create a minimal RUNNING row; a later snapshot (any seq) fills it', async () => {
    expect((await post('run-new', [ev(1)])).json.accepted).toBe(1);
    const d = h.idp.runs.detail('run-new', null);
    expect(d.run).toMatchObject({ status: 'RUNNING', hasSnapshot: false, snapshot: null });
    expect((await put(snapshot({ runId: 'run-new', seq: 0 }))).json.stored).toBe(true);
    expect(h.idp.runs.detail('run-new', null).run.hasSnapshot).toBe(true);
  });

  test(`retention: at most ${MAX_EVENTS_PER_RUN} events per run (oldest dropped)`, async () => {
    await put(snapshot());
    const total = MAX_EVENTS_PER_RUN + 60;
    for (let s = 0; s < total; s += 50) {
      const r = await post('run-20261012-abc', Array.from({ length: Math.min(50, total - s) }, (_, i) => ev(s + i)));
      expect(r.status).toBe(200);
    }
    const n = h.idp.db.prepare('SELECT COUNT(*) n, MIN(seq) lo, MAX(seq) hi FROM run_events WHERE run_id = ?').get('run-20261012-abc') as any;
    expect(n).toEqual({ n: MAX_EVENTS_PER_RUN, lo: 60, hi: total - 1 });
  });

  test(`retention: at most ${MAX_RUNS} runs, oldest finished dropped, active kept`, () => {
    const svc = h.idp.runs;
    svc.putSnapshot('active-old', snapshot({ runId: 'active-old', status: 'RUNNING' }));
    h.clock.now += 1;
    for (let i = 0; i < MAX_RUNS; i++) {
      svc.putSnapshot(`done-${i}`, snapshot({ runId: `done-${i}`, status: 'COMPLETED' }));
      svc.appendEvents(`done-${i}`, { events: [ev(1)] });
      h.clock.now += 1;
    }
    const ids = (h.idp.db.prepare('SELECT run_id FROM runs').all() as { run_id: string }[]).map((r) => r.run_id);
    expect(ids).toHaveLength(MAX_RUNS);
    expect(ids).toContain('active-old');
    expect(ids).not.toContain('done-0');
    expect(ids).toContain(`done-${MAX_RUNS - 1}`);
    const orphan = h.idp.db.prepare("SELECT COUNT(*) n FROM run_events WHERE run_id = 'done-0'").get() as { n: number };
    expect(orphan.n).toBe(0);
  });

  test('monitor data never influences approvals: pendingApprovalId in a snapshot does not approve anything', async () => {
    const body = approvalBody(h);
    await h.bearer('POST', '/api/approval-requests', body);
    await put(snapshot({ pendingApprovalId: body.requestId, status: 'COMPLETED', seq: 9 }));
    await post('run-20261012-abc', [ev(10, { type: 'DECISION_ANSWERED', message: 'APPROVED' }), ev(11, { type: 'MANDATE_SEALED', message: 'approved' })]);
    expect((await h.bearer('GET', `/api/approval-requests/${body.requestId}`)).json).toEqual({ requestId: body.requestId, status: 'PENDING' });
  });
});

describe('run monitor UI read endpoints', () => {
  let h: Harness;
  beforeEach(async () => { h = await startHarness(); });
  afterEach(async () => { await h.close(); });

  test('require a passkey session; list, active filter, detail with sinceSeq; staleness inputs', async () => {
    h.idp.runs.putSnapshot('r-active', snapshot({ runId: 'r-active' }));
    h.idp.runs.putSnapshot('r-done', snapshot({ runId: 'r-done', status: 'COMPLETED' }));
    h.idp.runs.appendEvents('r-active', { events: [ev(1), ev(2)] });
    const anon = h.browser();
    expect((await anon.req('GET', '/api/ui/runs')).status).toBe(401);
    expect((await anon.req('GET', '/api/ui/runs/r-active')).status).toBe(401);
    const { browser } = await enroll(h);
    const all = await browser.req('GET', '/api/ui/runs');
    expect(all.json.runs.map((r: any) => r.runId).sort()).toEqual(['r-active', 'r-done']);
    const act = await browser.req('GET', '/api/ui/runs?active=1');
    expect(act.json.runs.map((r: any) => r.runId)).toEqual(['r-active']);
    const d = await browser.req('GET', '/api/ui/runs/r-active?sinceSeq=1');
    expect(d.json.events.map((e: any) => e.seq)).toEqual([2]);
    expect(d.json.run.snapshot.tasks).toHaveLength(2);
    expect(typeof d.json.serverTime).toBe('string');
    expect(typeof d.json.run.receivedAt).toBe('string');
    expect((await browser.req('GET', '/api/ui/runs/nope')).status).toBe(404);
    expect((await browser.req('GET', '/api/ui/runs/r-active?sinceSeq=abc')).status).toBe(400);
    expect((await browser.req('GET', '/api/ui/runs/bad%20id')).status).toBe(400);
  });
});

describe('migration 3 upgrades a live v2 database in place', () => {
  test('passkey, approvals and decisions survive; login still works; runs tables appear', async () => {
    const dir = tmpDir();
    const h1 = await startHarness({ dataDir: dir });
    const auth = new SoftAuthenticator({ origin: ORIGIN, rpId: RP_ID });
    await enroll(h1, auth);
    const body = approvalBody(h1);
    await h1.bearer('POST', '/api/approval-requests', body);
    const kid = h1.idp.key.kid;
    const token = h1.idp.clientToken;
    await h1.close();
    // Turn it into an exact v2 database (as on Nazif-PC): drop the v3 objects and its migration row.
    const raw = new DatabaseSync(`${dir}/idp.sqlite`);
    raw.exec('DROP TABLE run_events; DROP TABLE runs; DELETE FROM schema_migrations WHERE version = 3;');
    expect((raw.prepare('SELECT MAX(version) v FROM schema_migrations').get() as { v: number }).v).toBe(2);
    raw.close();

    const h2 = await startHarness({ dataDir: dir });
    try {
      expect((h2.idp.db.prepare('SELECT MAX(version) v FROM schema_migrations').get() as { v: number }).v).toBe(3);
      expect(h2.idp.setupCode).toBeUndefined();
      expect(h2.idp.key.kid).toBe(kid);
      expect(h2.idp.clientToken).toBe(token);
      expect((h2.idp.db.prepare('SELECT COUNT(*) n FROM webauthn_credentials').get() as { n: number }).n).toBe(1);
      expect((await h2.bearer('GET', `/api/approval-requests/${body.requestId}`)).json.status).toBe('PENDING');
      const b = h2.browser();
      await b.req('GET', '/api/ui/state');
      const lo = await b.req('POST', '/api/auth/login/options', {});
      expect((await b.req('POST', '/api/auth/login/verify', { response: auth.authenticate(lo.json) })).status).toBe(200);
      expect((await h2.bearer('PUT', '/api/runs/run-x', snapshot({ runId: 'run-x' }))).status).toBe(200);
      expect((await b.req('GET', '/api/ui/runs')).json.runs).toHaveLength(1);
    } finally {
      await h2.close();
    }
  });
});
