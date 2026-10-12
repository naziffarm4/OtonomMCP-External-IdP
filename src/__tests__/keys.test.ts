import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { loadConfig } from '../config';
import { jwkThumbprint, safeEqual } from '../keys';
import { startHarness, tmpDir } from './helpers';

describe('signing key, JWKS and client token', () => {
  test('ES256 key is generated once, persisted with 0600 and reused across restarts', async () => {
    const dir = tmpDir();
    const h1 = await startHarness({ dataDir: dir });
    const kid = h1.idp.key.kid;
    const pemFile = path.join(dir, 'signing-key.pem');
    expect(fs.existsSync(pemFile)).toBe(true);
    if (process.platform !== 'win32') expect(fs.statSync(pemFile).mode & 0o777).toBe(0o600);
    expect(h1.logs.join('\n')).not.toContain('PRIVATE KEY');
    await h1.close();
    const h2 = await startHarness({ dataDir: dir });
    expect(h2.idp.key.kid).toBe(kid);
    expect(h2.logs.join('\n')).not.toMatch(/Generated new ES256/);
    const rows = h2.idp.db.prepare('SELECT kid, active FROM signing_keys').all() as { kid: string; active: number }[];
    expect(rows).toEqual([{ kid, active: 1 }]);
    await h2.close();
  });

  test('kid is the RFC 7638 thumbprint; JWKS and PEM endpoints publish the same key', async () => {
    const h = await startHarness();
    try {
      const jwks = await (await fetch(`${h.base}/.well-known/jwks.json`)).json();
      expect(jwks.keys).toHaveLength(1);
      const k = jwks.keys[0];
      expect(k).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig', kid: h.idp.key.kid });
      expect(k.d).toBeUndefined();
      expect(jwkThumbprint(k)).toBe(k.kid);
      const pemRes = await fetch(`${h.base}/api/public-key.pem`);
      expect(pemRes.headers.get('x-key-id')).toBe(h.idp.key.kid);
      const pem = await pemRes.text();
      expect(pem).toContain('BEGIN PUBLIC KEY');
      expect(fs.readFileSync(path.join(h.dataDir, 'public-key.pem'), 'utf8')).toBe(pem);
      const a = crypto.createPublicKey(pem).export({ format: 'jwk' }) as any;
      expect([a.x, a.y]).toEqual([k.x, k.y]);
    } finally {
      await h.close();
    }
  });

  test('client token generated on first start (0600 file, path logged, value not logged) and stable', async () => {
    const dir = tmpDir();
    const h1 = await startHarness({ dataDir: dir });
    const file = path.join(dir, 'client-token.txt');
    const tok = fs.readFileSync(file, 'utf8').trim();
    expect(tok).toBe(h1.idp.clientToken);
    expect(tok.length).toBeGreaterThanOrEqual(32);
    if (process.platform !== 'win32') expect(fs.statSync(file).mode & 0o777).toBe(0o600);
    expect(h1.logs.join('\n')).toContain(file);
    expect(h1.logs.join('\n')).not.toContain(tok);
    await h1.close();
    const h2 = await startHarness({ dataDir: dir });
    expect(h2.idp.clientToken).toBe(tok);
    await h2.close();
  });

  test('IDP_CLIENT_TOKEN env wins and must be long enough', async () => {
    const t = 'e'.repeat(40);
    const h = await startHarness({ env: { IDP_CLIENT_TOKEN: t } });
    try {
      expect(h.idp.clientToken).toBe(t);
      expect((await h.bearer('GET', '/api/status', undefined, t)).status).toBe(200);
    } finally {
      await h.close();
    }
    expect(() => loadConfig({ IDP_CLIENT_TOKEN: 'short' })).toThrow(/32/);
  });

  test('config defaults follow the contract and validate RP ID vs origin', () => {
    const c = loadConfig({});
    expect(c).toMatchObject({ host: '127.0.0.1', port: 7443, issuer: 'otonommcp-external-idp', audience: 'otonommcp', rpId: 'localhost', origin: 'http://localhost:7443', tokenTtlSeconds: 300 });
    expect(() => loadConfig({ IDP_RP_ID: 'example.com' })).toThrow(/RP_ID/);
    expect(() => loadConfig({ IDP_TOKEN_TTL_SECONDS: '600' })).toThrow();
  });

  test('safeEqual is exact', () => {
    expect(safeEqual('abc', 'abc')).toBe(true);
    expect(safeEqual('abc', 'abd')).toBe(false);
    expect(safeEqual('abc', 'abcd')).toBe(false);
  });
});
