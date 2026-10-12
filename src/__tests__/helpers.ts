import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { loadConfig, type IdpConfig } from '../config';
import { createIdp, type Idp } from '../server';
import { BrowserClient } from '../testing/browser-client';
import { SoftAuthenticator } from '../testing/soft-authenticator';

export const ORIGIN = 'http://localhost:7443';
export const RP_ID = 'localhost';

export interface Harness {
  idp: Idp;
  base: string;
  dataDir: string;
  clock: { now: number };
  logs: string[];
  bearer(method: string, p: string, body?: unknown, token?: string): Promise<{ status: number; json: any; headers: Headers }>;
  browser(): BrowserClient;
  close(): Promise<void>;
}

export function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'idp-test-'));
}

export async function startHarness(opts: { dataDir?: string; env?: Record<string, string>; cfg?: Partial<IdpConfig> } = {}): Promise<Harness> {
  const dataDir = opts.dataDir ?? tmpDir();
  const clock = { now: Date.now() };
  const logs: string[] = [];
  const cfg = loadConfig(
    { IDP_PORT: '0', IDP_DATA_DIR: dataDir, IDP_ORIGIN: ORIGIN, IDP_RP_ID: RP_ID, IDP_AUTH_RATE_LIMIT: '1000', ...(opts.env ?? {}) },
    { log: (m) => logs.push(m), now: () => clock.now, ...(opts.cfg ?? {}) },
  );
  const idp = createIdp(cfg);
  const { port } = await idp.listen();
  const base = `http://127.0.0.1:${port}`;
  return {
    idp,
    base,
    dataDir,
    clock,
    logs,
    async bearer(method, p, body, token = idp.clientToken) {
      const headers: Record<string, string> = { Accept: 'application/json' };
      if (token) headers.Authorization = `Bearer ${token}`;
      if (body !== undefined) headers['Content-Type'] = 'application/json';
      const res = await fetch(base + p, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
      const text = await res.text();
      let json: any;
      try { json = text ? JSON.parse(text) : undefined; } catch { json = text; }
      return { status: res.status, json, headers: res.headers };
    },
    browser: () => new BrowserClient(base, ORIGIN),
    close: () => idp.close(),
  };
}

/** Runs first-run setup with a software authenticator; returns a logged-in browser. */
export async function enroll(h: Harness, auth = new SoftAuthenticator({ origin: ORIGIN, rpId: RP_ID })) {
  const b = h.browser();
  await b.req('GET', '/api/ui/state');
  const opts = await b.req('POST', '/api/setup/options', { setupCode: h.idp.setupCode, username: 'nazif', displayName: 'Nazif Açıkgöz' });
  if (opts.status !== 200) throw new Error(`setup options failed: ${JSON.stringify(opts.json)}`);
  const ver = await b.req('POST', '/api/setup/verify', { response: auth.register(opts.json) });
  if (ver.status !== 200) throw new Error(`setup verify failed: ${JSON.stringify(ver.json)}`);
  return { browser: b, auth };
}

export function approvalBody(h: Harness, over: Record<string, unknown> = {}) {
  const now = h.clock.now;
  return {
    requestId: crypto.randomUUID(),
    projectId: 'proj-LLMTEST',
    packageId: 'pkg-p15-LLMTEST-v1',
    revision: 3,
    contextFingerprint: 'sha256:ctx-' + crypto.randomBytes(8).toString('hex'),
    specFingerprint: 'sha256:spec-' + crypto.randomBytes(8).toString('hex'),
    directorSessionId: 'dir-sess-b864b11fb7b14ed1',
    taskId: 'TASK-001',
    operation: 'autonomous.start',
    nonce: crypto.randomBytes(18).toString('base64url'),
    summary: { title: 'Otonom çalıştırmayı başlat', budgetUsd: 3, tasks: 8 },
    requestedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 10 * 60_000).toISOString(),
    ...over,
  };
}

export function decisionBody(h: Harness, over: Record<string, unknown> = {}) {
  const now = h.clock.now;
  return {
    decisionId: crypto.randomUUID(),
    projectId: 'proj-LLMTEST',
    runId: 'run-42',
    taskId: 'TASK-007',
    packageId: 'pkg-autonomous-abc123-def45678',
    revision: 1,
    operation: 'AUTONOMOUS_DECISION',
    contextFingerprint: 'sha256:ctx-' + crypto.randomBytes(8).toString('hex'),
    question: 'Veritabanı olarak hangisini kullanalım?',
    options: [
      { id: 'sqlite', label: 'SQLite', description: 'Tek dosya, kurulum yok' },
      { id: 'postgres', label: 'PostgreSQL', description: 'Sunucu gerekir' },
    ],
    allowFreeText: true,
    recommendedOptionId: 'sqlite',
    nonce: crypto.randomBytes(18).toString('base64url'),
    summary: 'Director iki seçenek arasında karar veremedi.',
    requestedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 10 * 60_000).toISOString(),
    ...over,
  };
}

export function decodeJwt(token: string): { header: any; payload: any } {
  const [h, p] = token.split('.');
  return { header: JSON.parse(Buffer.from(h, 'base64url').toString()), payload: JSON.parse(Buffer.from(p, 'base64url').toString()) };
}
