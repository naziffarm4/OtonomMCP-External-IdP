import { SoftAuthenticator } from '../testing/soft-authenticator';
import { ORIGIN, RP_ID, enroll, startHarness, type Harness } from './helpers';

describe('WebAuthn registration and authentication (real @simplewebauthn verification)', () => {
  let h: Harness;
  beforeEach(async () => { h = await startHarness(); });
  afterEach(async () => { await h.close(); });

  test('first run prints a one-time setup code and reports needsSetup', async () => {
    expect(h.idp.setupCode).toMatch(/^[0-9A-F]{6}-[0-9A-F]{6}-[0-9A-F]{6}$/);
    expect(h.logs.join('\n')).toContain(h.idp.setupCode!);
    const b = h.browser();
    const s = await b.req('GET', '/api/ui/state');
    expect(s.json).toMatchObject({ needsSetup: true, user: null });
  });

  test('setup with passkey creates PRODUCT_OWNER and a session; setup code is single-use', async () => {
    const { browser } = await enroll(h);
    const s = await browser.req('GET', '/api/ui/state');
    expect(s.json.needsSetup).toBe(false);
    expect(s.json.user).toMatchObject({ username: 'nazif', role: 'PRODUCT_OWNER' });
    const b2 = h.browser();
    await b2.req('GET', '/api/ui/state');
    const again = await b2.req('POST', '/api/setup/options', { setupCode: h.idp.setupCode, username: 'evil' });
    expect(again.status).toBe(409);
    const users = h.idp.db.prepare('SELECT COUNT(*) n FROM users').get() as { n: number };
    expect(users.n).toBe(1);
    expect(h.idp.db.prepare("SELECT value FROM meta WHERE key='setup_code_hash'").get()).toBeUndefined();
  });

  test('wrong setup code is rejected', async () => {
    const b = h.browser();
    await b.req('GET', '/api/ui/state');
    const r = await b.req('POST', '/api/setup/options', { setupCode: 'AAAAAA-BBBBBB-CCCCCC', username: 'nazif' });
    expect(r.status).toBe(403);
  });

  test('IDP_SETUP_CODE env is honoured', async () => {
    const h2 = await startHarness({ env: { IDP_SETUP_CODE: 'my-fixed-setup-code' } });
    try {
      expect(h2.idp.setupCode).toBeUndefined();
      const b = h2.browser();
      await b.req('GET', '/api/ui/state');
      const r = await b.req('POST', '/api/setup/options', { setupCode: 'my-fixed-setup-code', username: 'nazif' });
      expect(r.status).toBe(200);
      expect(r.json.authenticatorSelection).toMatchObject({ userVerification: 'required', residentKey: 'required' });
      expect(r.json.rp.id).toBe('localhost');
    } finally {
      await h2.close();
    }
  });

  test('registration from a wrong origin is rejected', async () => {
    const b = h.browser();
    await b.req('GET', '/api/ui/state');
    const opts = await b.req('POST', '/api/setup/options', { setupCode: h.idp.setupCode, username: 'nazif' });
    const auth = new SoftAuthenticator({ origin: ORIGIN, rpId: RP_ID });
    const r = await b.req('POST', '/api/setup/verify', { response: auth.register(opts.json, { origin: 'http://evil.example' }) });
    expect(r.status).toBe(401);
    expect(r.json.message).toMatch(/origin/i);
  });

  test('registration without user verification is rejected', async () => {
    const b = h.browser();
    await b.req('GET', '/api/ui/state');
    const opts = await b.req('POST', '/api/setup/options', { setupCode: h.idp.setupCode, username: 'nazif' });
    const auth = new SoftAuthenticator({ origin: ORIGIN, rpId: RP_ID, userVerified: false });
    const r = await b.req('POST', '/api/setup/verify', { response: auth.register(opts.json) });
    expect(r.status).toBe(401);
    expect(h.idp.auth.needsSetup()).toBe(true);
  });

  test('registration for a wrong RP ID is rejected', async () => {
    const b = h.browser();
    await b.req('GET', '/api/ui/state');
    const opts = await b.req('POST', '/api/setup/options', { setupCode: h.idp.setupCode, username: 'nazif' });
    const auth = new SoftAuthenticator({ origin: ORIGIN, rpId: RP_ID });
    const r = await b.req('POST', '/api/setup/verify', { response: auth.register(opts.json, { rpId: 'evil.example' }) });
    expect(r.status).toBe(401);
  });

  test('setup challenge cannot be used from another browser (flow cookie binding)', async () => {
    const b = h.browser();
    await b.req('GET', '/api/ui/state');
    const opts = await b.req('POST', '/api/setup/options', { setupCode: h.idp.setupCode, username: 'nazif' });
    const attacker = h.browser();
    await attacker.req('GET', '/api/ui/state');
    const auth = new SoftAuthenticator({ origin: ORIGIN, rpId: RP_ID });
    const r = await attacker.req('POST', '/api/setup/verify', { response: auth.register(opts.json) });
    expect(r.status).toBe(401);
    expect(r.json.message).toMatch(/bound/);
  });

  test('passkey login works and creates a fresh session', async () => {
    const { auth } = await enroll(h);
    const b = h.browser();
    await b.req('GET', '/api/ui/state');
    const opts = await b.req('POST', '/api/auth/login/options', {});
    expect(opts.json.userVerification).toBe('required');
    const r = await b.req('POST', '/api/auth/login/verify', { response: auth.authenticate(opts.json) });
    expect(r.status).toBe(200);
    expect(b.cookies.get('idp_session')).toBeTruthy();
    const pend = await b.req('GET', '/api/ui/pending');
    expect(pend.status).toBe(200);
  });

  async function loginAttempt(auth: SoftAuthenticator, override: Parameters<SoftAuthenticator['authenticate']>[1] = {}) {
    const b = h.browser();
    await b.req('GET', '/api/ui/state');
    const opts = await b.req('POST', '/api/auth/login/options', {});
    return { b, opts: opts.json, res: await b.req('POST', '/api/auth/login/verify', { response: auth.authenticate(opts.json, override) }) };
  }

  test('login negative: wrong origin', async () => {
    const { auth } = await enroll(h);
    expect((await loginAttempt(auth, { origin: 'http://localhost.evil:7443' })).res.status).toBe(401);
  });

  test('login negative: no user verification', async () => {
    const { auth } = await enroll(h);
    auth.opts.userVerified = false;
    const r = await loginAttempt(auth);
    expect(r.res.status).toBe(401);
    expect(r.b.cookies.get('idp_session')).toBeUndefined();
  });

  test('login negative: replayed challenge / replayed response', async () => {
    const { auth } = await enroll(h);
    const { b, opts, res } = await loginAttempt(auth);
    expect(res.status).toBe(200);
    const replay = await b.req('POST', '/api/auth/login/verify', { response: auth.authenticate(opts) });
    expect(replay.status).toBe(401);
    expect(replay.json.message).toMatch(/already used/);
  });

  test('login negative: failed attempt burns the challenge', async () => {
    const { auth } = await enroll(h);
    const b = h.browser();
    await b.req('GET', '/api/ui/state');
    const opts = await b.req('POST', '/api/auth/login/options', {});
    const bad = await b.req('POST', '/api/auth/login/verify', { response: auth.authenticate(opts.json, { origin: 'http://evil' }) });
    expect(bad.status).toBe(401);
    const good = await b.req('POST', '/api/auth/login/verify', { response: auth.authenticate(opts.json) });
    expect(good.status).toBe(401);
  });

  test('login negative: counter regression (cloned authenticator)', async () => {
    const { auth } = await enroll(h);
    expect((await loginAttempt(auth)).res.status).toBe(200); // counter 1
    expect((await loginAttempt(auth)).res.status).toBe(200); // counter 2
    const r = await loginAttempt(auth, { counter: 1 });
    expect(r.res.status).toBe(401);
    expect(r.res.json.message).toMatch(/counter/i);
  });

  test('login negative: unknown credential', async () => {
    await enroll(h);
    const stranger = new SoftAuthenticator({ origin: ORIGIN, rpId: RP_ID });
    expect((await loginAttempt(stranger)).res.status).toBe(401);
  });

  test('expired challenge is rejected', async () => {
    const { auth } = await enroll(h);
    const b = h.browser();
    await b.req('GET', '/api/ui/state');
    const opts = await b.req('POST', '/api/auth/login/options', {});
    h.clock.now += 6 * 60_000;
    const r = await b.req('POST', '/api/auth/login/verify', { response: auth.authenticate(opts.json) });
    expect(r.status).toBe(401);
    expect(r.json.message).toMatch(/expired/);
  });

  test('cross-origin POSTs and missing CSRF tokens are refused', async () => {
    const { browser } = await enroll(h);
    const noOrigin = await browser.req('POST', '/api/auth/login/options', {}, { Origin: 'http://evil.example' });
    expect(noOrigin.status).toBe(403);
    const crossSite = await browser.req('POST', '/api/auth/logout', {}, { 'Sec-Fetch-Site': 'cross-site' });
    expect(crossSite.status).toBe(403);
    const noCsrf = await browser.req('POST', '/api/auth/logout', {}, { 'X-CSRF-Token': 'wrong' });
    expect(noCsrf.status).toBe(403);
    expect(noCsrf.json.error).toBe('CSRF');
    const ok = await browser.req('POST', '/api/auth/logout', {});
    expect(ok.status).toBe(200);
    expect((await browser.req('GET', '/api/ui/pending')).status).toBe(401);
  });

  test('a second passkey can be added by a logged-in user', async () => {
    const { browser } = await enroll(h);
    const opts = await browser.req('POST', '/api/passkeys/options', {});
    expect(opts.status).toBe(200);
    expect(opts.json.excludeCredentials).toHaveLength(1);
    const second = new SoftAuthenticator({ origin: ORIGIN, rpId: RP_ID });
    const r = await browser.req('POST', '/api/passkeys/verify', { response: second.register(opts.json) });
    expect(r.status).toBe(200);
    expect((await loginAttempt(second)).res.status).toBe(200);
  });

  test('login endpoints are rate limited', async () => {
    const h2 = await startHarness({ env: { IDP_AUTH_RATE_LIMIT: '3' } });
    try {
      const b = h2.browser();
      await b.req('GET', '/api/ui/state');
      const codes: number[] = [];
      for (let i = 0; i < 5; i++) codes.push((await b.req('POST', '/api/auth/login/options', {})).status);
      expect(codes.slice(0, 3)).toEqual([200, 200, 200]);
      expect(codes[4]).toBe(429);
    } finally {
      await h2.close();
    }
  });
});
