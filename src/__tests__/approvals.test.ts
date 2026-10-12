import * as crypto from 'node:crypto';
import { verifyEs256 } from '../jwt';
import { SoftAuthenticator } from '../testing/soft-authenticator';
import { ORIGIN, RP_ID, approvalBody, decodeJwt, enroll, startHarness, type Harness } from './helpers';

describe('approval state machine and decision tokens', () => {
  let h: Harness;
  beforeEach(async () => { h = await startHarness(); });
  afterEach(async () => { await h.close(); });

  async function create(over: Record<string, unknown> = {}) {
    const body = approvalBody(h, over);
    const r = await h.bearer('POST', '/api/approval-requests', body);
    expect(r.status).toBe(201);
    return body;
  }

  async function approveVia(browser: any, auth: SoftAuthenticator, id: string, optsFor = id) {
    const opts = await browser.req('POST', `/api/ui/approvals/${optsFor}/options`, {});
    expect(opts.status).toBe(200);
    return browser.req('POST', `/api/ui/approvals/${id}/approve`, { assertion: auth.authenticate(opts.json) });
  }

  test('full flow: create -> PENDING -> passkey approve -> APPROVED with ES256 token carrying every contract claim', async () => {
    const { browser, auth } = await enroll(h);
    const body = await create();
    const created = await h.bearer('GET', `/api/approval-requests/${body.requestId}`);
    expect(created.json).toEqual({ requestId: body.requestId, status: 'PENDING' });

    const detail = await browser.req('GET', `/api/ui/approvals/${body.requestId}`);
    expect(detail.json).toMatchObject({ projectId: body.projectId, packageId: body.packageId, revision: 3, nonce: body.nonce, summary: body.summary });

    const opts = await browser.req('POST', `/api/ui/approvals/${body.requestId}/options`, {});
    expect(opts.json.userVerification).toBe('required');
    expect(opts.json.allowCredentials.map((c: any) => c.id)).toEqual([auth.id]);
    const ok = await browser.req('POST', `/api/ui/approvals/${body.requestId}/approve`, { assertion: auth.authenticate(opts.json) });
    expect(ok.status).toBe(200);

    const st = await h.bearer('GET', `/api/approval-requests/${body.requestId}`);
    expect(st.json.status).toBe('APPROVED');
    const { header, payload } = decodeJwt(st.json.token);
    expect(header).toEqual({ alg: 'ES256', typ: 'JWT', kid: h.idp.key.kid });
    expect(payload).toMatchObject({
      iss: 'otonommcp-external-idp', aud: 'otonommcp', actorRole: 'PRODUCT_OWNER', nonce: body.nonce, requestId: body.requestId,
      decision: 'APPROVED', amr: ['webauthn'], uv: true, projectId: body.projectId, packageId: body.packageId, revision: 3,
      contextFingerprint: body.contextFingerprint, directorSessionId: body.directorSessionId, taskId: body.taskId, operation: body.operation,
    });
    expect(typeof payload.sub).toBe('string');
    expect(payload.jti).toMatch(/^[0-9a-f-]{36}$/);
    expect(payload.nbf).toBe(payload.iat);
    expect(payload.exp - payload.iat).toBeLessThanOrEqual(300);

    // verify against the published JWKS key
    const jwks = await h.bearer('GET', '/.well-known/jwks.json', undefined, '');
    const pub = crypto.createPublicKey({ key: jwks.json.keys[0], format: 'jwk' });
    expect(() => verifyEs256(st.json.token, pub, h.idp.key.kid, { issuer: 'otonommcp-external-idp', audience: 'otonommcp', now: h.clock.now })).not.toThrow();
    // tampering breaks the signature
    const [hh, pp, ss] = st.json.token.split('.');
    const forged = Buffer.from(JSON.stringify({ ...payload, revision: 4 })).toString('base64url');
    expect(() => verifyEs256(`${hh}.${forged}.${ss}`, pub, h.idp.key.kid, { issuer: 'otonommcp-external-idp', audience: 'otonommcp', now: h.clock.now })).toThrow(/signature/);
    void pp;

    const audit = h.idp.db.prepare("SELECT event FROM audit_log WHERE target_id = ? ORDER BY id").all(body.requestId) as { event: string }[];
    expect(audit.map((a) => a.event)).toEqual(['approval.created', 'approval.approved']);
  });

  test('optional binding claims are omitted when not supplied', async () => {
    const { browser, auth } = await enroll(h);
    const body = approvalBody(h);
    delete (body as any).directorSessionId;
    delete (body as any).taskId;
    expect((await h.bearer('POST', '/api/approval-requests', body)).status).toBe(201);
    expect((await approveVia(browser, auth, body.requestId)).status).toBe(200);
    const { payload } = decodeJwt((await h.bearer('GET', `/api/approval-requests/${body.requestId}`)).json.token);
    expect(payload).not.toHaveProperty('directorSessionId');
    expect(payload).not.toHaveProperty('taskId');
  });

  test('approve without a passkey assertion is refused', async () => {
    const { browser } = await enroll(h);
    const body = await create();
    const r = await browser.req('POST', `/api/ui/approvals/${body.requestId}/approve`, {});
    expect(r.status).toBe(401);
    expect(r.json.error).toBe('ASSERTION_REQUIRED');
    expect((await h.bearer('GET', `/api/approval-requests/${body.requestId}`)).json.status).toBe('PENDING');
  });

  test('service layer refuses approval without a verified credential (no unsafe default)', async () => {
    await enroll(h);
    const body = await create();
    const user = h.idp.db.prepare('SELECT * FROM users').get() as any;
    expect(() => h.idp.requests.approve(body.requestId, user, '')).toThrow(/assertion/);
  });

  test('assertion bound to a different requestId cannot approve this one', async () => {
    const { browser, auth } = await enroll(h);
    const a = await create();
    const b = await create();
    const r = await approveVia(browser, auth, b.requestId, a.requestId);
    expect(r.status).toBe(401);
    expect(r.json.message).toMatch(/different request/);
    expect((await h.bearer('GET', `/api/approval-requests/${b.requestId}`)).json.status).toBe('PENDING');
  });

  test('login challenge cannot be reused as an approval assertion', async () => {
    const { browser, auth } = await enroll(h);
    const body = await create();
    const loginOpts = await browser.req('POST', '/api/auth/login/options', {});
    const r = await browser.req('POST', `/api/ui/approvals/${body.requestId}/approve`, { assertion: auth.authenticate(loginOpts.json) });
    expect(r.status).toBe(401);
  });

  test('approval assertion without UV is refused', async () => {
    const { browser, auth } = await enroll(h);
    const body = await create();
    auth.opts.userVerified = false;
    expect((await approveVia(browser, auth, body.requestId)).status).toBe(401);
  });

  test('another session cannot use my approval challenge', async () => {
    const { browser, auth } = await enroll(h);
    const body = await create();
    const opts = await browser.req('POST', `/api/ui/approvals/${body.requestId}/options`, {});
    // second login session of same user
    const b2 = h.browser();
    await b2.req('GET', '/api/ui/state');
    const lo = await b2.req('POST', '/api/auth/login/options', {});
    await b2.req('POST', '/api/auth/login/verify', { response: auth.authenticate(lo.json) });
    const r = await b2.req('POST', `/api/ui/approvals/${body.requestId}/approve`, { assertion: auth.authenticate(opts.json) });
    expect(r.status).toBe(401);
  });

  test('expired requests cannot be approved and report EXPIRED', async () => {
    const { browser, auth } = await enroll(h);
    const body = await create({ expiresAt: new Date(h.clock.now + 60_000).toISOString() });
    const opts = await browser.req('POST', `/api/ui/approvals/${body.requestId}/options`, {});
    h.clock.now += 61_000;
    const r = await browser.req('POST', `/api/ui/approvals/${body.requestId}/approve`, { assertion: auth.authenticate(opts.json) });
    expect(r.status).toBe(409);
    expect(r.json.error).toBe('EXPIRED');
    const st = await h.bearer('GET', `/api/approval-requests/${body.requestId}`);
    expect(st.json.status).toBe('EXPIRED');
    expect(st.json.token).toBeUndefined();
    expect((await browser.req('POST', `/api/ui/approvals/${body.requestId}/options`, {})).status).toBe(409);
  });

  test('each request can be decided only once', async () => {
    const { browser, auth } = await enroll(h);
    const body = await create();
    expect((await approveVia(browser, auth, body.requestId)).status).toBe(200);
    expect((await browser.req('POST', `/api/ui/approvals/${body.requestId}/options`, {})).status).toBe(409);
    expect((await browser.req('POST', `/api/ui/approvals/${body.requestId}/reject`, { reason: 'late' })).status).toBe(409);
    const user = h.idp.db.prepare('SELECT * FROM users').get() as any;
    expect(() => h.idp.requests.approve(body.requestId, user, auth.id)).toThrow(/already/);
  });

  test('reject with reason: REJECTED, reason visible, no token', async () => {
    const { browser } = await enroll(h);
    const body = await create();
    expect((await browser.req('POST', `/api/ui/approvals/${body.requestId}/reject`, {})).status).toBe(400);
    const r = await browser.req('POST', `/api/ui/approvals/${body.requestId}/reject`, { reason: 'Bütçe çok yüksek <script>' });
    expect(r.status).toBe(200);
    const st = await h.bearer('GET', `/api/approval-requests/${body.requestId}`);
    expect(st.json).toMatchObject({ status: 'REJECTED', reason: 'Bütçe çok yüksek <script>' });
    expect(st.json.token).toBeUndefined();
  });

  test('UI routes require a session', async () => {
    const body = await create();
    const anon = h.browser();
    expect((await anon.req('GET', '/api/ui/pending')).status).toBe(401);
    expect((await anon.req('GET', `/api/ui/approvals/${body.requestId}`)).status).toBe(401);
    expect((await anon.req('POST', `/api/ui/approvals/${body.requestId}/options`, {})).status).toBe(401);
  });

  test('pending list contains approvals', async () => {
    const { browser } = await enroll(h);
    const body = await create();
    const p = await browser.req('GET', '/api/ui/pending');
    expect(p.json.approvals.map((a: any) => a.requestId)).toEqual([body.requestId]);
  });

  test('state persists across restart (approved token still served)', async () => {
    const { browser, auth } = await enroll(h);
    const body = await create();
    await approveVia(browser, auth, body.requestId);
    const token = (await h.bearer('GET', `/api/approval-requests/${body.requestId}`)).json.token;
    const dir = h.dataDir;
    await h.close();
    h = await startHarness({ dataDir: dir });
    expect(h.idp.setupCode).toBeUndefined();
    const st = await h.bearer('GET', `/api/approval-requests/${body.requestId}`);
    expect(st.json).toMatchObject({ status: 'APPROVED', token });
    void SoftAuthenticator; void ORIGIN; void RP_ID;
  });
});
