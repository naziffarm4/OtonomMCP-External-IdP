import * as crypto from 'node:crypto';
import { approvalBody, startHarness, type Harness } from './helpers';

describe('OtonomMCP machine API', () => {
  let h: Harness;
  beforeEach(async () => { h = await startHarness(); });
  afterEach(async () => { await h.close(); });

  test('healthz answers fast without auth', async () => {
    const t = Date.now();
    const r = await h.bearer('GET', '/healthz', undefined, '');
    expect(r.status).toBe(200);
    expect(r.json.ok).toBe(true);
    expect(Date.now() - t).toBeLessThan(5000);
  });

  test('status/heartbeat requires bearer and reports kid, issuer, pending counts', async () => {
    expect((await h.bearer('GET', '/api/status', undefined, '')).status).toBe(401);
    const r = await h.bearer('GET', '/api/status');
    expect(r.json).toMatchObject({ status: 'ok', issuer: 'otonommcp-external-idp', audience: 'otonommcp', kid: h.idp.key.kid, setupRequired: true, pending: { approvals: 0, decisions: 0 } });
  });

  test('bearer auth: missing, malformed, wrong token are 401 with WWW-Authenticate', async () => {
    const body = approvalBody(h);
    for (const tok of ['', 'short', crypto.randomBytes(32).toString('base64url')]) {
      const r = await h.bearer('POST', '/api/approval-requests', body, tok);
      expect(r.status).toBe(401);
      expect(r.headers.get('www-authenticate')).toBe('Bearer');
    }
    expect((await h.bearer('GET', `/api/approval-requests/${body.requestId}`, undefined, '')).status).toBe(401);
  });

  test('create returns 201 with approvalUrl', async () => {
    const body = approvalBody(h);
    const r = await h.bearer('POST', '/api/approval-requests', body);
    expect(r.status).toBe(201);
    expect(r.json).toMatchObject({ requestId: body.requestId, status: 'PENDING', approvalUrl: `http://localhost:7443/#/approvals/${body.requestId}` });
  });

  test('summary in the OtonomMCP shape (arrays of strings, null ids) is accepted', async () => {
    const body = approvalBody(h, {
      directorSessionId: null, taskId: null, operation: 'AUTONOMOUS_SPEC_RUN',
      contextFingerprint: 'a'.repeat(64), specFingerprint: 'b'.repeat(64),
      summary: { projectName: 'LLMTEST', specPath: 'C:\\aidm-live\\specs\\x.md', budgetUsd: 5, taskCount: 8, allowedPaths: ['src', 'tests'], mandateHours: 8, text: 'Otonom çalıştırma' },
    });
    const r = await h.bearer('POST', '/api/approval-requests', body);
    expect(r.status).toBe(201);
    expect((await h.bearer('POST', '/api/approval-requests', approvalBody(h, { summary: { a: [{ x: 1 }] } }))).status).toBe(400);
  });

  test('duplicate requestId and duplicate nonce are rejected with 409', async () => {
    const body = approvalBody(h);
    await h.bearer('POST', '/api/approval-requests', body);
    expect((await h.bearer('POST', '/api/approval-requests', { ...approvalBody(h), requestId: body.requestId })).status).toBe(409);
    expect((await h.bearer('POST', '/api/approval-requests', { ...approvalBody(h), nonce: body.nonce })).status).toBe(409);
  });

  const now = () => Date.now();
  test.each([
    ['requestId not uuid', { requestId: 'abc' }],
    ['revision zero', { revision: 0 }],
    ['revision string', { revision: '3' }],
    ['nonce too short', { nonce: 'abc' }],
    ['nonce with spaces', { nonce: 'a a a a a a a a a a a a a' }],
    ['projectId with space', { projectId: 'a b' }],
    ['missing operation', { operation: undefined }],
    ['missing summary', { summary: undefined }],
    ['summary nested object', { summary: { a: { b: 1 } } }],
    ['summary with control chars', { summary: 'hello\u0007' }],
    ['summary bidi override', { summary: 'evil\u202Etxt' }],
    ['expiresAt > 15 min', { expiresAt: new Date(now() + 16 * 60_000).toISOString() }],
    ['expiresAt in the past', { expiresAt: new Date(now() - 1000).toISOString() }],
    ['requestedAt in the future', { requestedAt: new Date(now() + 5 * 60_000).toISOString(), expiresAt: new Date(now() + 10 * 60_000).toISOString() }],
    ['bad timestamp format', { requestedAt: 'yesterday' }],
    ['timestamp without zone', { requestedAt: '2026-10-12T10:00:00' }],
    ['unknown field', { approved: true }],
  ])('validation: %s -> 400', async (_n, over) => {
    const body: any = { ...approvalBody(h), ...over };
    for (const k of Object.keys(body)) if (body[k] === undefined) delete body[k];
    const r = await h.bearer('POST', '/api/approval-requests', body);
    expect(r.status).toBe(400);
    expect(r.json.error).toBe('VALIDATION_ERROR');
  });

  test('non-JSON content type -> 415, bad JSON -> 400, oversize body -> 413', async () => {
    const headers = { Authorization: `Bearer ${h.idp.clientToken}` };
    let r = await fetch(`${h.base}/api/approval-requests`, { method: 'POST', headers: { ...headers, 'Content-Type': 'text/plain' }, body: '{}' });
    expect(r.status).toBe(415);
    r = await fetch(`${h.base}/api/approval-requests`, { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' }, body: '{nope' });
    expect(r.status).toBe(400);
    r = await fetch(`${h.base}/api/approval-requests`, { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify({ x: 'a'.repeat(70_000) }) });
    expect(r.status).toBe(413);
  });

  test('unknown request -> 404; GET with non-uuid path -> 404', async () => {
    expect((await h.bearer('GET', `/api/approval-requests/${crypto.randomUUID()}`)).status).toBe(404);
    expect((await h.bearer('GET', '/api/approval-requests/../../etc/passwd')).status).toBe(404);
  });

  test('security headers on API and static responses', async () => {
    for (const p of ['/healthz', '/', '/app.js']) {
      const r = await fetch(h.base + p);
      expect(r.headers.get('content-security-policy')).toContain("script-src 'self'");
      expect(r.headers.get('content-security-policy')).not.toContain('unsafe-inline');
      expect(r.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
      expect(r.headers.get('x-content-type-options')).toBe('nosniff');
      expect(r.headers.get('x-frame-options')).toBe('DENY');
    }
    expect((await fetch(`${h.base}/healthz`)).headers.get('cache-control')).toBe('no-store');
  });

  test('foreign Host header is refused (DNS rebinding defence)', async () => {
    const http = await import('node:http');
    const port = new URL(h.base).port;
    const status = await new Promise<number>((resolve) => {
      http.get({ host: '127.0.0.1', port, path: '/healthz', headers: { Host: 'attacker.example' } }, (res) => { res.resume(); resolve(res.statusCode!); });
    });
    expect(status).toBe(421);
  });

  test('vendored @simplewebauthn/browser bundle is served locally', async () => {
    const r = await fetch(`${h.base}/vendor/simplewebauthn-browser.js`);
    expect(r.status).toBe(200);
    expect(await r.text()).toContain('SimpleWebAuthnBrowser');
  });

  test('API is rate limited per client', async () => {
    const h2 = await startHarness({ env: { IDP_API_RATE_LIMIT: '2' } });
    try {
      const codes = [];
      for (let i = 0; i < 4; i++) codes.push((await h2.bearer('GET', '/api/status')).status);
      expect(codes).toEqual([200, 200, 429, 429]);
    } finally {
      await h2.close();
    }
  });
});
