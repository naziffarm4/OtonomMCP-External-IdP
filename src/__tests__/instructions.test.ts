import { DatabaseSync } from 'node:sqlite';
import { verifyEs256 } from '../jwt';
import { SoftAuthenticator } from '../testing/soft-authenticator';
import { ORIGIN, RP_ID, decodeJwt, enroll, startHarness, tmpDir, type Harness } from './helpers';
import { snapshot } from './runs.test';

const RUN = 'run-instr-1';
function channel(over: Record<string, unknown> = {}) {
  return { runId: RUN, projectId: 'LLMTEST', packageId: 'pkg-autonomous-abc-123', revision: 1, contextFingerprint: 'a'.repeat(64), openedAt: new Date().toISOString(), ...over };
}

describe('live instructions', () => {
  let h: Harness;
  beforeEach(async () => {
    h = await startHarness();
    h.idp.runs.putSnapshot(RUN, snapshot({ runId: RUN }));
  });
  afterEach(async () => { await h.close(); });

  const openChannel = (over: Record<string, unknown> = {}) => h.bearer('PUT', `/api/runs/${RUN}/instruction-channel`, channel(over));

  async function send(browser: any, auth: SoftAuthenticator, draft: Record<string, unknown>) {
    const o = await browser.req('POST', `/api/ui/runs/${RUN}/instructions/options`, draft);
    if (o.status !== 200) return o;
    return browser.req('POST', `/api/ui/runs/${RUN}/instructions/${o.json.instructionId}`, { assertion: auth.authenticate(o.json.options) });
  }

  test('full flow: channel -> passkey-signed instruction -> token with every contract claim -> poll -> ack', async () => {
    const { browser, auth } = await enroll(h);
    expect((await openChannel()).json).toEqual({ runId: RUN, open: true });
    const o = await browser.req('POST', `/api/ui/runs/${RUN}/instructions/options`, { mode: 'PAUSE_AND_APPLY', text: 'Dur, iletişim formu ekle', taskId: 'TASK-002' });
    expect(o.status).toBe(200);
    expect(o.json.options.userVerification).toBe('required');
    const id = o.json.instructionId;
    const r = await browser.req('POST', `/api/ui/runs/${RUN}/instructions/${id}`, { assertion: auth.authenticate(o.json.options) });
    expect(r.json).toEqual({ instructionId: id, status: 'PENDING_DELIVERY' });

    const poll = await h.bearer('GET', `/api/runs/${RUN}/instructions?status=PENDING_DELIVERY`);
    expect(poll.json.instructions).toHaveLength(1);
    const it0 = poll.json.instructions[0];
    expect(it0).toMatchObject({ instructionId: id, mode: 'PAUSE_AND_APPLY' });
    const { header, payload } = decodeJwt(it0.token);
    expect(header).toEqual({ alg: 'ES256', typ: 'JWT', kid: h.idp.key.kid });
    expect(payload).toMatchObject({
      iss: 'otonommcp-external-idp', aud: 'otonommcp', preferred_username: 'nazif', actorRole: 'PRODUCT_OWNER', instructionId: id, runId: RUN,
      projectId: 'LLMTEST', packageId: 'pkg-autonomous-abc-123', revision: 1, contextFingerprint: 'a'.repeat(64), operation: 'AUTONOMOUS_INSTRUCTION',
      mode: 'PAUSE_AND_APPLY', text: 'Dur, iletişim formu ekle', taskId: 'TASK-002', amr: ['webauthn'], uv: true,
    });
    expect(payload.nonce.length).toBeGreaterThanOrEqual(16);
    expect(payload.exp - payload.iat).toBeLessThanOrEqual(900);
    expect(payload.nbf).toBe(payload.iat);
    expect(() => verifyEs256(it0.token, h.idp.key.publicKeyPem, h.idp.key.kid, { issuer: 'otonommcp-external-idp', audience: 'otonommcp', now: h.clock.now })).not.toThrow();

    expect((await h.bearer('POST', `/api/runs/${RUN}/instructions/${id}/ack`, { status: 'RECEIVED' })).json.status).toBe('RECEIVED');
    expect((await h.bearer('GET', `/api/runs/${RUN}/instructions?status=PENDING_DELIVERY`)).json.instructions).toEqual([]);
    expect((await h.bearer('POST', `/api/runs/${RUN}/instructions/${id}/ack`, { status: 'RECEIVED' })).status).toBe(409);
    expect((await h.bearer('POST', `/api/runs/${RUN}/instructions/${id}/ack`, { status: 'APPLIED', note: 'Form eklendi, 2 görev güncellendi' })).json.status).toBe('APPLIED');
    expect((await h.bearer('POST', `/api/runs/${RUN}/instructions/${id}/ack`, { status: 'REJECTED' })).status).toBe(409);

    const ui = await browser.req('GET', `/api/ui/runs/${RUN}`);
    expect(ui.json.instructionChannel).toMatchObject({ open: true, canInstruct: true, revision: 1 });
    expect(ui.json.instructions[0]).toMatchObject({ instructionId: id, status: 'APPLIED', note: 'Form eklendi, 2 görev güncellendi', text: 'Dur, iletişim formu ekle' });
    expect(JSON.stringify(ui.json)).not.toContain(it0.token); // tokens never go to the browser
  });

  test('NOTE and STOP modes; STOP text optional; taskId null when not targeted', async () => {
    const { browser, auth } = await enroll(h);
    await openChannel();
    expect((await send(browser, auth, { mode: 'NOTE', text: 'Renkleri koyu yap' })).status).toBe(200);
    expect((await send(browser, auth, { mode: 'STOP' })).status).toBe(200);
    const list = (await h.bearer('GET', `/api/runs/${RUN}/instructions`)).json.instructions;
    expect(list.map((i: any) => i.mode)).toEqual(['NOTE', 'STOP']);
    const stop = decodeJwt(list[1].token).payload;
    expect(stop.text).toBe('');
    expect(stop.taskId).toBeNull();
  });

  test.each([
    ['bad mode', { mode: 'KILL', text: 'x' }],
    ['missing text for NOTE', { mode: 'NOTE' }],
    ['empty text for PAUSE_AND_APPLY', { mode: 'PAUSE_AND_APPLY', text: '   ' }],
    ['text too long', { mode: 'NOTE', text: 'x'.repeat(2001) }],
    ['taskId too long', { mode: 'NOTE', text: 'x', taskId: 'y'.repeat(129) }],
    ['unknown field', { mode: 'NOTE', text: 'x', priority: 'high' }],
    ['control chars', { mode: 'NOTE', text: 'a\u0007b' }],
  ])('form validation: %s -> 400', async (_n, draft) => {
    const { browser } = await enroll(h);
    await openChannel();
    expect((await browser.req('POST', `/api/ui/runs/${RUN}/instructions/options`, draft)).status).toBe(400);
  });

  test('no channel / closed channel / finished run -> 409, form hidden', async () => {
    const { browser, auth } = await enroll(h);
    expect((await send(browser, auth, { mode: 'NOTE', text: 'x' })).status).toBe(409);
    await openChannel();
    expect((await h.bearer('DELETE', `/api/runs/${RUN}/instruction-channel`)).json).toEqual({ runId: RUN, open: false });
    expect((await send(browser, auth, { mode: 'NOTE', text: 'x' })).status).toBe(409);
    expect((await browser.req('GET', `/api/ui/runs/${RUN}`)).json.instructionChannel.canInstruct).toBe(false);
    await openChannel();
    h.idp.runs.putSnapshot(RUN, snapshot({ runId: RUN, seq: 9, status: 'COMPLETED' }));
    expect((await send(browser, auth, { mode: 'NOTE', text: 'x' })).status).toBe(409);
  });

  test('channel closed between options and submit -> 409, nothing stored', async () => {
    const { browser, auth } = await enroll(h);
    await openChannel();
    const o = await browser.req('POST', `/api/ui/runs/${RUN}/instructions/options`, { mode: 'NOTE', text: 'x' });
    await h.bearer('DELETE', `/api/runs/${RUN}/instruction-channel`);
    const r = await browser.req('POST', `/api/ui/runs/${RUN}/instructions/${o.json.instructionId}`, { assertion: auth.authenticate(o.json.options) });
    expect(r.status).toBe(409);
    expect((h.idp.db.prepare('SELECT COUNT(*) n FROM instructions').get() as { n: number }).n).toBe(0);
  });

  test('re-PUT channel updates revision/contextFingerprint used in new tokens', async () => {
    const { browser, auth } = await enroll(h);
    await openChannel();
    await openChannel({ revision: 2, contextFingerprint: 'b'.repeat(64) });
    await send(browser, auth, { mode: 'NOTE', text: 'x' });
    const p = decodeJwt((await h.bearer('GET', `/api/runs/${RUN}/instructions`)).json.instructions[0].token).payload;
    expect([p.revision, p.contextFingerprint]).toEqual([2, 'b'.repeat(64)]);
  });

  test('step-up binding: no assertion, wrong instructionId, other run, replay, no UV, CSRF', async () => {
    const { browser, auth } = await enroll(h);
    await openChannel();
    const o = await browser.req('POST', `/api/ui/runs/${RUN}/instructions/options`, { mode: 'NOTE', text: 'x' });
    const id = o.json.instructionId;
    expect((await browser.req('POST', `/api/ui/runs/${RUN}/instructions/${id}`, {})).status).toBe(401);
    // assertion was not consumed by the empty call (it never parsed) -> now try binding to another instructionId
    const o2 = await browser.req('POST', `/api/ui/runs/${RUN}/instructions/options`, { mode: 'NOTE', text: 'y' });
    const cross = await browser.req('POST', `/api/ui/runs/${RUN}/instructions/${o2.json.instructionId}`, { assertion: auth.authenticate(o.json.options) });
    expect(cross.status).toBe(401);
    expect(cross.json.message).toMatch(/different request|already used/);
    // other run path with the right instructionId
    h.idp.runs.putSnapshot('run-other', snapshot({ runId: 'run-other' }));
    const o3 = await browser.req('POST', `/api/ui/runs/${RUN}/instructions/options`, { mode: 'NOTE', text: 'z' });
    expect((await browser.req('POST', `/api/ui/runs/run-other/instructions/${o3.json.instructionId}`, { assertion: auth.authenticate(o3.json.options) })).status).toBe(401);
    // replay of a successful assertion
    const o4 = await browser.req('POST', `/api/ui/runs/${RUN}/instructions/options`, { mode: 'NOTE', text: 'ok' });
    const a4 = auth.authenticate(o4.json.options);
    expect((await browser.req('POST', `/api/ui/runs/${RUN}/instructions/${o4.json.instructionId}`, { assertion: a4 })).status).toBe(200);
    expect((await browser.req('POST', `/api/ui/runs/${RUN}/instructions/${o4.json.instructionId}`, { assertion: a4 })).status).toBe(401);
    // no user verification
    const o5 = await browser.req('POST', `/api/ui/runs/${RUN}/instructions/options`, { mode: 'NOTE', text: 'uv' });
    auth.opts.userVerified = false;
    expect((await browser.req('POST', `/api/ui/runs/${RUN}/instructions/${o5.json.instructionId}`, { assertion: auth.authenticate(o5.json.options) })).status).toBe(401);
    auth.opts.userVerified = true;
    // CSRF / Origin
    expect((await browser.req('POST', `/api/ui/runs/${RUN}/instructions/options`, { mode: 'NOTE', text: 'x' }, { 'X-CSRF-Token': 'bad' })).status).toBe(403);
    expect((await browser.req('POST', `/api/ui/runs/${RUN}/instructions/options`, { mode: 'NOTE', text: 'x' }, { Origin: 'http://evil.example' })).status).toBe(403);
    expect((await h.browser().req('POST', `/api/ui/runs/${RUN}/instructions/options`, { mode: 'NOTE', text: 'x' })).status).toBe(401);
    expect((h.idp.db.prepare('SELECT COUNT(*) n FROM instructions').get() as { n: number }).n).toBe(1);
  });

  test('the signed content is what was shown at options time (submit body cannot change it)', async () => {
    const { browser, auth } = await enroll(h);
    await openChannel();
    const o = await browser.req('POST', `/api/ui/runs/${RUN}/instructions/options`, { mode: 'NOTE', text: 'masum not' });
    await browser.req('POST', `/api/ui/runs/${RUN}/instructions/${o.json.instructionId}`, { assertion: auth.authenticate(o.json.options), mode: 'STOP', text: 'kötü' });
    const p = decodeJwt((await h.bearer('GET', `/api/runs/${RUN}/instructions`)).json.instructions[0].token).payload;
    expect([p.mode, p.text]).toEqual(['NOTE', 'masum not']);
  });

  test('expiry: not received within 15 min -> EXPIRED, no longer delivered, ack 409', async () => {
    const { browser, auth } = await enroll(h);
    await openChannel();
    await send(browser, auth, { mode: 'NOTE', text: 'x' });
    const id = (await h.bearer('GET', `/api/runs/${RUN}/instructions`)).json.instructions[0].instructionId;
    h.clock.now += 15 * 60_000 + 1000;
    expect((await h.bearer('GET', `/api/runs/${RUN}/instructions?status=PENDING_DELIVERY`)).json.instructions).toEqual([]);
    expect((await h.bearer('POST', `/api/runs/${RUN}/instructions/${id}/ack`, { status: 'RECEIVED' })).status).toBe(409);
    expect((await browser.req('GET', `/api/ui/runs/${RUN}`)).json.instructions[0].status).toBe('EXPIRED');
  });

  test('ack: PENDING_DELIVERY -> REJECTED with reason allowed; validation and auth', async () => {
    const { browser, auth } = await enroll(h);
    await openChannel();
    await send(browser, auth, { mode: 'NOTE', text: 'x' });
    const id = (await h.bearer('GET', `/api/runs/${RUN}/instructions`)).json.instructions[0].instructionId;
    expect((await h.bearer('POST', `/api/runs/${RUN}/instructions/${id}/ack`, { status: 'APPLIED' })).status).toBe(409);
    expect((await h.bearer('POST', `/api/runs/${RUN}/instructions/${id}/ack`, { status: 'DONE' })).status).toBe(400);
    expect((await h.bearer('POST', `/api/runs/${RUN}/instructions/${id}/ack`, { status: 'REJECTED', note: 'x'.repeat(1001) })).status).toBe(400);
    expect((await h.bearer('POST', `/api/runs/${RUN}/instructions/${id}/ack`, { status: 'REJECTED', extra: 1 })).status).toBe(400);
    expect((await h.bearer('POST', `/api/runs/run-other/instructions/${id}/ack`, { status: 'RECEIVED' })).status).toBe(404);
    expect((await h.bearer('POST', `/api/runs/${RUN}/instructions/${id}/ack`, { status: 'RECEIVED' }, '')).status).toBe(401);
    expect((await h.bearer('POST', `/api/runs/${RUN}/instructions/${id}/ack`, { status: 'REJECTED', note: 'revision mismatch' })).json.status).toBe('REJECTED');
    expect((await h.bearer('GET', `/api/runs/${RUN}/instructions?status=APPLIED`)).status).toBe(400);
  });

  test.each([
    ['runId mismatch', { runId: 'x' }],
    ['revision 0', { revision: 0 }],
    ['fingerprint too long', { contextFingerprint: 'a'.repeat(201) }],
    ['unknown field', { budgetUsd: 100 }],
    ['bad openedAt', { openedAt: 'now' }],
  ])('channel validation: %s -> 400', async (_n, over) => {
    expect((await openChannel(over)).status).toBe(400);
  });

  test('channel endpoints require bearer; DELETE unknown -> 404', async () => {
    expect((await h.bearer('PUT', `/api/runs/${RUN}/instruction-channel`, channel(), '')).status).toBe(401);
    expect((await h.bearer('DELETE', `/api/runs/${RUN}/instruction-channel`)).status).toBe(404);
    expect((await h.bearer('GET', `/api/runs/${RUN}/instructions`, undefined, '')).status).toBe(401);
  });
});

describe('migration 4 upgrades a live v3 database in place', () => {
  test('enrolled passkey survives, login works, instruction flow works after upgrade', async () => {
    const dir = tmpDir();
    const h1 = await startHarness({ dataDir: dir });
    const auth = new SoftAuthenticator({ origin: ORIGIN, rpId: RP_ID });
    await enroll(h1, auth);
    h1.idp.runs.putSnapshot(RUN, snapshot({ runId: RUN }));
    await h1.close();
    const raw = new DatabaseSync(`${dir}/idp.sqlite`);
    raw.exec(`DROP TABLE IF EXISTS resume_requests; DROP TABLE instructions; DROP TABLE instruction_channels; DROP TABLE webauthn_challenges;
      CREATE TABLE webauthn_challenges (id TEXT PRIMARY KEY, challenge TEXT NOT NULL UNIQUE,
        purpose TEXT NOT NULL CHECK (purpose IN ('setup','register','login','approve','decide')), binding_hash TEXT NOT NULL,
        user_id TEXT, target_id TEXT, payload TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER);
      ALTER TABLE decision_requests DROP COLUMN questions; ALTER TABLE decision_answers DROP COLUMN answers;
      DELETE FROM schema_migrations WHERE version >= 4;`);
    raw.close();
    const h2 = await startHarness({ dataDir: dir });
    try {
      expect((h2.idp.db.prepare('SELECT MAX(version) v FROM schema_migrations').get() as { v: number }).v).toBe(6);
      expect(h2.idp.runs.detail(RUN, null).run.status).toBe('RUNNING');
      const b = h2.browser();
      await b.req('GET', '/api/ui/state');
      const lo = await b.req('POST', '/api/auth/login/options', {});
      expect((await b.req('POST', '/api/auth/login/verify', { response: auth.authenticate(lo.json) })).status).toBe(200);
      await h2.bearer('PUT', `/api/runs/${RUN}/instruction-channel`, channel());
      const o = await b.req('POST', `/api/ui/runs/${RUN}/instructions/options`, { mode: 'NOTE', text: 'yükseltme sonrası' });
      expect((await b.req('POST', `/api/ui/runs/${RUN}/instructions/${o.json.instructionId}`, { assertion: auth.authenticate(o.json.options) })).status).toBe(200);
    } finally {
      await h2.close();
    }
  });
});
