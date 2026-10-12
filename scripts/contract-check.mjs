#!/usr/bin/env node
/**
 * CONTRACT CHECK: issues a real approval token through the full IdP flow
 * (setup -> passkey login -> approval request -> WebAuthn step-up -> token) using a
 * software authenticator, then verifies it with OtonomMCP's actual
 * OidcIdentityProviderAdapter (pinned public key PEM).
 *
 * Usage:
 *   npm run contract-check                                  # OtonomMCP at ../OtonomMCP
 *   OTONOMMCP_DIR=D:\ÇALIŞMALAR-D\OtonomMCP npm run contract-check
 *   OTONOMMCP_ADAPTER=/path/to/trusted-identity-adapters.js npm run contract-check
 * OtonomMCP must be built (packages/core/dist) from a branch that contains the IdP wiring.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL, fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const dist = path.resolve(here, '..', 'dist');
const { loadConfig } = require(path.join(dist, 'config.js'));
const { createIdp } = require(path.join(dist, 'server.js'));
const { SoftAuthenticator } = require(path.join(dist, 'testing', 'soft-authenticator.js'));
const { BrowserClient } = require(path.join(dist, 'testing', 'browser-client.js'));

const adapterPath = process.env.OTONOMMCP_ADAPTER
  ?? path.join(path.resolve(process.env.OTONOMMCP_DIR ?? path.resolve(here, '..', '..', 'OtonomMCP')), 'packages', 'core', 'dist', 'authorization', 'trusted-identity-adapters.js');
if (!fs.existsSync(adapterPath)) {
  console.error(`OtonomMCP adapter not found at ${adapterPath}. Build OtonomMCP or set OTONOMMCP_DIR / OTONOMMCP_ADAPTER.`);
  process.exit(2);
}
const { OidcIdentityProviderAdapter } = await import(pathToFileURL(adapterPath).href);

const ORIGIN = 'http://localhost:7443';
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'idp-contract-'));
const cfg = loadConfig({ IDP_PORT: '0', IDP_DATA_DIR: dataDir, IDP_ORIGIN: ORIGIN }, { log: () => {} });
const idp = createIdp(cfg);
const { port } = await idp.listen();
const base = `http://127.0.0.1:${port}`;
const results = [];
const check = (name, ok, detail = '') => { results.push({ name, ok }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`); };

try {
  const auth = new SoftAuthenticator({ origin: ORIGIN, rpId: 'localhost' });
  const b = new BrowserClient(base, ORIGIN);
  await b.req('GET', '/api/ui/state');
  const so = await b.req('POST', '/api/setup/options', { setupCode: idp.setupCode, username: 'nazif', displayName: 'Nazif' });
  await b.req('POST', '/api/setup/verify', { response: auth.register(so.json) });

  const now = Date.now();
  const binding = {
    projectId: 'LLMTEST', packageId: 'pkg-autonomous-LLMTEST-1', revision: 1,
    contextFingerprint: 'c'.repeat(64), operation: 'AUTONOMOUS_SPEC_RUN',
  };
  const requestId = crypto.randomUUID();
  const nonce = Buffer.from(crypto.getRandomValues(new Uint8Array(18))).toString('base64url');
  const created = await fetch(`${base}/api/approval-requests`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${idp.clientToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ requestId, ...binding, specFingerprint: 's'.repeat(64), directorSessionId: null, taskId: null, nonce,
      summary: { text: 'contract check', allowedPaths: ['src'] }, requestedAt: new Date(now).toISOString(), expiresAt: new Date(now + 600_000).toISOString() }),
  });
  check('POST /api/approval-requests -> 201', created.status === 201);
  const opts = await b.req('POST', `/api/ui/approvals/${requestId}/options`, {});
  const appr = await b.req('POST', `/api/ui/approvals/${requestId}/approve`, { assertion: auth.authenticate(opts.json) });
  check('WebAuthn step-up approval', appr.status === 200, JSON.stringify(appr.json));
  const st = await (await fetch(`${base}/api/approval-requests/${requestId}`, { headers: { Authorization: `Bearer ${idp.clientToken}` } })).json();
  check('GET status -> APPROVED with token', st.status === 'APPROVED' && typeof st.token === 'string');
  const pem = await (await fetch(`${base}/api/public-key.pem`)).text();

  const adapter = new OidcIdentityProviderAdapter({ issuer: 'otonommcp-external-idp', audience: 'otonommcp', publicKeyPem: pem });
  const ok = await adapter.verifyAssertion({ token: st.token, binding }, binding, { dryRun: true });
  check('adapter ACCEPTS token with correct binding', ok.isValid === true, ok.isValid ? ok.status : `${ok.status}: ${ok.reason}`);

  const [h, p, s] = st.token.split('.');
  const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
  const forged = `${h}.${Buffer.from(JSON.stringify({ ...payload, projectId: 'OTHER' })).toString('base64url')}.${s}`;
  const t1 = await adapter.verifyAssertion({ token: forged, binding: { ...binding, projectId: 'OTHER' } }, { ...binding, projectId: 'OTHER' }, { dryRun: true });
  check('adapter REJECTS tampered payload', !t1.isValid, t1.status);
  const t2 = await adapter.verifyAssertion({ token: st.token, binding: { ...binding, revision: 2 } }, { ...binding, revision: 2 }, { dryRun: true });
  check('adapter REJECTS wrong binding (revision)', !t2.isValid && t2.status === 'BINDING_MISMATCH', t2.status);
  const t3 = await adapter.verifyAssertion({ token: st.token, binding }, { ...binding, contextFingerprint: 'd'.repeat(64) }, { dryRun: true });
  check('adapter REJECTS wrong contextFingerprint', !t3.isValid, t3.status);
  const otherAud = new OidcIdentityProviderAdapter({ issuer: 'otonommcp-external-idp', audience: 'someone-else', publicKeyPem: pem });
  const t4 = await otherAud.verifyAssertion({ token: st.token, binding }, binding, { dryRun: true });
  check('adapter REJECTS wrong audience', !t4.isValid && t4.status === 'AUDIENCE_MISMATCH', t4.status);
  const { generateKeyPairSync } = await import('node:crypto');
  const otherPem = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ type: 'spki', format: 'pem' });
  const wrongKey = new OidcIdentityProviderAdapter({ issuer: 'otonommcp-external-idp', audience: 'otonommcp', publicKeyPem: otherPem });
  const t5 = await wrongKey.verifyAssertion({ token: st.token, binding }, binding, { dryRun: true });
  check('adapter REJECTS token under a different pinned key', !t5.isValid && t5.status === 'SIGNATURE_INVALID', t5.status);
} finally {
  await idp.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
}
const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} contract checks passed (adapter: ${adapterPath})`);
process.exit(failed ? 1 : 0);
