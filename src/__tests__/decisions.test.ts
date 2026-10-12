import * as crypto from 'node:crypto';
import { verifyEs256 } from '../jwt';
import { decisionBody, decodeJwt, enroll, startHarness, type Harness } from './helpers';

describe('decision requests (Director asks the user to choose)', () => {
  let h: Harness;
  beforeEach(async () => { h = await startHarness(); });
  afterEach(async () => { await h.close(); });

  async function create(over: Record<string, unknown> = {}) {
    const body = decisionBody(h, over);
    const r = await h.bearer('POST', '/api/decision-requests', body);
    expect(r.status).toBe(201);
    expect(r.json).toMatchObject({ decisionId: body.decisionId, status: 'PENDING', decisionUrl: `http://localhost:7443/#/decisions/${body.decisionId}` });
    return body;
  }

  async function answer(browser: any, auth: any, id: string, payload: Record<string, unknown>, optsFor = id) {
    const opts = await browser.req('POST', `/api/ui/decisions/${optsFor}/options`, {});
    expect(opts.status).toBe(200);
    return browser.req('POST', `/api/ui/decisions/${id}/answer`, { ...payload, assertion: auth.authenticate(opts.json) });
  }

  test('full flow with selected option -> ANSWERED + ES256 answer token', async () => {
    const { browser, auth } = await enroll(h);
    const body = await create();
    expect((await h.bearer('GET', `/api/decision-requests/${body.decisionId}`)).json).toEqual({ decisionId: body.decisionId, status: 'PENDING' });
    const view = await browser.req('GET', `/api/ui/decisions/${body.decisionId}`);
    expect(view.json).toMatchObject({ question: body.question, recommendedOptionId: 'sqlite', allowFreeText: true, options: body.options });
    const r = await answer(browser, auth, body.decisionId, { selectedOptionId: 'postgres', freeText: 'Ölçeklenme için.' });
    expect(r.status).toBe(200);
    const st = await h.bearer('GET', `/api/decision-requests/${body.decisionId}`);
    expect(st.json.status).toBe('ANSWERED');
    const { header, payload } = decodeJwt(st.json.token);
    expect(header).toEqual({ alg: 'ES256', typ: 'JWT', kid: h.idp.key.kid });
    expect(payload).toMatchObject({
      iss: 'otonommcp-external-idp', aud: 'otonommcp', actorRole: 'PRODUCT_OWNER', nonce: body.nonce, decisionId: body.decisionId,
      selectedOptionId: 'postgres', freeText: 'Ölçeklenme için.', projectId: body.projectId, runId: body.runId, taskId: body.taskId,
      contextFingerprint: body.contextFingerprint, amr: ['webauthn'], uv: true,
    });
    expect(payload.exp - payload.iat).toBeLessThanOrEqual(300);
    expect(payload).not.toHaveProperty('decision');
    expect(() => verifyEs256(st.json.token, h.idp.key.publicKeyPem, h.idp.key.kid, { issuer: 'otonommcp-external-idp', audience: 'otonommcp', now: h.clock.now })).not.toThrow();
  });

  test('free text only answer (no option) is allowed when allowFreeText', async () => {
    const { browser, auth } = await enroll(h);
    const body = await create();
    expect((await answer(browser, auth, body.decisionId, { freeText: 'İkisi de değil, DuckDB.' })).status).toBe(200);
    const { payload } = decodeJwt((await h.bearer('GET', `/api/decision-requests/${body.decisionId}`)).json.token);
    expect(payload).not.toHaveProperty('selectedOptionId');
    expect(payload.freeText).toBe('İkisi de değil, DuckDB.');
  });

  test('selectedOptionId must be one of the options; invalid input does not burn the passkey challenge', async () => {
    const { browser, auth } = await enroll(h);
    const body = await create();
    const opts = await browser.req('POST', `/api/ui/decisions/${body.decisionId}/options`, {});
    const assertion = auth.authenticate(opts.json);
    const bad = await browser.req('POST', `/api/ui/decisions/${body.decisionId}/answer`, { selectedOptionId: 'mysql', assertion });
    expect(bad.status).toBe(400);
    const good = await browser.req('POST', `/api/ui/decisions/${body.decisionId}/answer`, { selectedOptionId: 'sqlite', assertion });
    expect(good.status).toBe(200);
  });

  test('free text refused when not allowed, and length-limited', async () => {
    const { browser, auth } = await enroll(h);
    const noFree = await create({ allowFreeText: false });
    expect((await answer(browser, auth, noFree.decisionId, { selectedOptionId: 'sqlite', freeText: 'x' })).status).toBe(400);
    const body = await create();
    expect((await answer(browser, auth, body.decisionId, { freeText: 'a'.repeat(2001) })).status).toBe(400);
    expect((await answer(browser, auth, body.decisionId, {})).status).toBe(400);
  });

  test('answer requires an assertion bound to this decisionId', async () => {
    const { browser, auth } = await enroll(h);
    const a = await create();
    const b = await create();
    expect((await browser.req('POST', `/api/ui/decisions/${a.decisionId}/answer`, { selectedOptionId: 'sqlite' })).status).toBe(401);
    const cross = await answer(browser, auth, b.decisionId, { selectedOptionId: 'sqlite' }, a.decisionId);
    expect(cross.status).toBe(401);
    expect(cross.json.message).toMatch(/different request/);
  });

  test('approval challenge cannot answer a decision with the same id space', async () => {
    const { browser, auth } = await enroll(h);
    const body = await create();
    auth.opts.userVerified = false;
    expect((await answer(browser, auth, body.decisionId, { selectedOptionId: 'sqlite' })).status).toBe(401);
  });

  test('answered once only; expired cannot be answered', async () => {
    const { browser, auth } = await enroll(h);
    const body = await create();
    expect((await answer(browser, auth, body.decisionId, { selectedOptionId: 'sqlite' })).status).toBe(200);
    expect((await browser.req('POST', `/api/ui/decisions/${body.decisionId}/options`, {})).status).toBe(409);
    const exp = await create({ expiresAt: new Date(h.clock.now + 30_000).toISOString() });
    const opts = await browser.req('POST', `/api/ui/decisions/${exp.decisionId}/options`, {});
    h.clock.now += 31_000;
    const r = await browser.req('POST', `/api/ui/decisions/${exp.decisionId}/answer`, { selectedOptionId: 'sqlite', assertion: auth.authenticate(opts.json) });
    expect(r.status).toBe(409);
    const st = await h.bearer('GET', `/api/decision-requests/${exp.decisionId}`);
    expect(st.json.status).toBe('EXPIRED');
    expect(st.json.token).toBeUndefined();
  });

  test('pending list shows decisions next to approvals', async () => {
    const { browser } = await enroll(h);
    const body = await create();
    const p = await browser.req('GET', '/api/ui/pending');
    expect(p.json.decisions.map((d: any) => d.decisionId)).toEqual([body.decisionId]);
    expect(p.json.approvals).toEqual([]);
  });

  test.each([
    ['too few options', { options: [{ id: 'a', label: 'A' }] }],
    ['too many options', { options: Array.from({ length: 7 }, (_, i) => ({ id: `o${i}`, label: `O${i}` })) }],
    ['duplicate option ids', { options: [{ id: 'a', label: 'A' }, { id: 'a', label: 'B' }] }],
    ['bad option id', { options: [{ id: 'a b', label: 'A' }, { id: 'c', label: 'C' }] }],
    ['unknown option field', { options: [{ id: 'a', label: 'A', html: '<b>' }, { id: 'c', label: 'C' }] }],
    ['recommended not in options', { recommendedOptionId: 'mysql' }],
    ['allowFreeText not boolean', { allowFreeText: 'yes' }],
    ['missing runId', { runId: undefined }],
    ['short nonce', { nonce: 'short' }],
    ['empty question', { question: '   ' }],
    ['expiry > 15 min', { expiresAt: new Date(Date.now() + 20 * 60_000).toISOString() }],
    ['unknown top-level field', { extra: 1 }],
  ])('validation: %s -> 400', async (_name, over) => {
    const body: any = decisionBody(h, over as any);
    for (const k of Object.keys(body)) if (body[k] === undefined) delete body[k];
    const r = await h.bearer('POST', '/api/decision-requests', body);
    expect(r.status).toBe(400);
  });

  test('duplicate decisionId / nonce rejected (also across approvals)', async () => {
    const body = await create();
    expect((await h.bearer('POST', '/api/decision-requests', { ...decisionBody(h), decisionId: body.decisionId })).status).toBe(409);
    expect((await h.bearer('POST', '/api/decision-requests', { ...decisionBody(h), nonce: body.nonce })).status).toBe(409);
    const appr = await h.bearer('POST', '/api/approval-requests', {
      requestId: crypto.randomUUID(), projectId: 'p', packageId: 'k', revision: 1, contextFingerprint: 'c', specFingerprint: 's',
      operation: 'op', nonce: body.nonce, summary: 'x', requestedAt: new Date(h.clock.now).toISOString(), expiresAt: new Date(h.clock.now + 60_000).toISOString(),
    });
    expect(appr.status).toBe(409);
  });

  test('decision endpoints require the bearer token', async () => {
    expect((await h.bearer('POST', '/api/decision-requests', decisionBody(h), '')).status).toBe(401);
    expect((await h.bearer('GET', `/api/decision-requests/${crypto.randomUUID()}`, undefined, 'x'.repeat(40))).status).toBe(401);
    expect((await h.bearer('GET', `/api/decision-requests/${crypto.randomUUID()}`)).status).toBe(404);
  });
});
