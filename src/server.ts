import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import * as path from 'node:path';
import { AuthService, type User } from './auth';
import type { IdpConfig } from './config';
import { openDatabase, type Db } from './db';
import { RateLimiter, SECURITY_HEADERS, cookie, parseCookies, readJson, sendError, sendJson } from './http-util';
import { loadOrCreateClientToken, loadOrCreateSigningKey, safeEqual, sha256Hex, type SigningKey } from './keys';
import { RequestService } from './requests';
import { RunMonitorService } from './runs';
import { InstructionService } from './instructions';
import * as nodeCrypto from 'node:crypto';
import { HttpError, asObject } from './validation';

export const VERSION = '2.0.0';
const FLOW_COOKIE = 'idp_flow';
const SESSION_COOKIE = 'idp_session';
const UUID_PATH = '([0-9a-fA-F-]{36})';

interface StaticFile {
  type: string;
  body: Buffer;
}

function loadStatic(): Record<string, StaticFile> {
  const pub = path.resolve(__dirname, '..', 'public');
  const files: Record<string, StaticFile> = {
    '/': { type: 'text/html; charset=utf-8', body: fs.readFileSync(path.join(pub, 'index.html')) },
    '/app.js': { type: 'text/javascript; charset=utf-8', body: fs.readFileSync(path.join(pub, 'app.js')) },
    '/app.css': { type: 'text/css; charset=utf-8', body: fs.readFileSync(path.join(pub, 'app.css')) },
  };
  // @simplewebauthn/browser UMD bundle served locally (no CDN).
  const browserEntry = require.resolve('@simplewebauthn/browser');
  const pkgRoot = browserEntry.slice(0, browserEntry.lastIndexOf(`${path.sep}script${path.sep}`));
  files['/vendor/simplewebauthn-browser.js'] = {
    type: 'text/javascript; charset=utf-8',
    body: fs.readFileSync(path.join(pkgRoot, 'dist', 'bundle', 'index.umd.min.js')),
  };
  return files;
}

export interface Idp {
  server: http.Server;
  db: Db;
  cfg: IdpConfig;
  key: SigningKey;
  auth: AuthService;
  requests: RequestService;
  runs: RunMonitorService;
  instructions: InstructionService;
  clientToken: string;
  /** Setup code generated on this start (undefined if already set up or provided by env). */
  setupCode?: string;
  startedAt: number;
  listen(): Promise<{ port: number; host: string }>;
  close(): Promise<void>;
}

export function createIdp(cfg: IdpConfig): Idp {
  const db = openDatabase(cfg.dataDir);
  const key = loadOrCreateSigningKey(db, cfg.dataDir, cfg.now(), cfg.log);
  const clientToken = loadOrCreateClientToken(cfg.dataDir, cfg.clientToken, cfg.log);
  const auth = new AuthService(db, cfg);
  const requests = new RequestService(db, cfg, key);
  const runs = new RunMonitorService(db, cfg);
  const instructions = new InstructionService(db, cfg, key);
  const setupCode = auth.ensureSetupCode();
  const statics = loadStatic();
  const limiter = new RateLimiter(cfg.now);
  const secureCookies = cfg.origin.startsWith('https:');
  const startedAt = cfg.now();
  const jwks = { keys: [key.publicJwk] };

  const server = http.createServer((req, res) => {
    handle(req, res).catch((err) => sendError(res, err, cfg.log));
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 15_000;
  server.keepAliveTimeout = 5_000;

  function allowedHosts(): Set<string> {
    const port = (server.address() as AddressInfo | null)?.port ?? cfg.port;
    return new Set([new URL(cfg.origin).host, `localhost:${port}`, `127.0.0.1:${port}`, `[::1]:${port}`]);
  }

  function clientIp(req: http.IncomingMessage): string {
    return req.socket.remoteAddress ?? 'unknown';
  }

  function rateLimit(req: http.IncomingMessage, bucket: string, limit: number): void {
    if (!limiter.check(`${bucket}:${clientIp(req)}`, limit)) {
      throw new HttpError(429, 'RATE_LIMITED', 'Too many requests, slow down');
    }
  }

  function requireBearer(req: http.IncomingMessage): void {
    rateLimit(req, 'api', cfg.apiRateLimitPerMinute);
    const h = String(req.headers.authorization ?? '');
    const m = /^Bearer ([A-Za-z0-9._~+/=-]{16,512})$/.exec(h);
    if (!m || !safeEqual(m[1], clientToken)) throw new HttpError(401, 'UNAUTHORIZED', 'Missing or invalid bearer token');
  }

  /** Browser POSTs must come from our own origin (CSRF defence layer 1, also covers pre-login flows). */
  function requireSameOrigin(req: http.IncomingMessage): void {
    const origin = req.headers.origin;
    if (origin !== cfg.origin) throw new HttpError(403, 'BAD_ORIGIN', 'Cross-origin request rejected');
    const site = req.headers['sec-fetch-site'];
    if (site !== undefined && site !== 'same-origin') throw new HttpError(403, 'BAD_ORIGIN', 'Cross-site request rejected');
  }

  function flowHash(req: http.IncomingMessage, res: http.ServerResponse): string {
    let flow = parseCookies(req.headers.cookie)[FLOW_COOKIE];
    if (!flow || !/^[A-Za-z0-9_-]{43}$/.test(flow)) {
      flow = crypto.randomBytes(32).toString('base64url');
      appendCookie(res, cookie(FLOW_COOKIE, flow, { secure: secureCookies, maxAge: 3600 }));
    }
    return sha256Hex(`flow:${flow}`);
  }

  function appendCookie(res: http.ServerResponse, c: string): void {
    const prev = res.getHeader('Set-Cookie');
    const list = Array.isArray(prev) ? prev : prev ? [String(prev)] : [];
    res.setHeader('Set-Cookie', [...list, c]);
  }

  function session(req: http.IncomingMessage) {
    return auth.getSession(parseCookies(req.headers.cookie)[SESSION_COOKIE]);
  }

  /** Cookie-authenticated route guard. State-changing calls also need same Origin + X-CSRF-Token. */
  function requireSession(req: http.IncomingMessage, mutating: boolean): { user: User; idHash: string; csrf: string } {
    const s = session(req);
    if (!s) throw new HttpError(401, 'LOGIN_REQUIRED', 'Please sign in with your passkey');
    if (mutating) {
      requireSameOrigin(req);
      const t = req.headers['x-csrf-token'];
      if (typeof t !== 'string' || !safeEqual(t, s.csrf)) throw new HttpError(403, 'CSRF', 'Missing or invalid CSRF token');
    }
    return s;
  }

  function startSession(res: http.ServerResponse, userId: string): string {
    const { cookie: c, csrf } = auth.createSession(userId);
    appendCookie(res, cookie(SESSION_COOKIE, c, { secure: secureCookies, maxAge: cfg.sessionTtlSeconds }));
    // rotate the pre-login flow cookie so a captured value can't be reused
    appendCookie(res, cookie(FLOW_COOKIE, '', { secure: secureCookies, maxAge: 0 }));
    return csrf;
  }

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const host = String(req.headers.host ?? '');
    if (!allowedHosts().has(host)) throw new HttpError(421, 'BAD_HOST', 'Unexpected Host header');
    const url = new URL(req.url ?? '/', 'http://local');
    const p = url.pathname;
    const method = req.method ?? 'GET';
    let m: RegExpExecArray | null;

    // ---------- public ----------
    if (method === 'GET' && p === '/healthz') {
      db.prepare('SELECT 1').get();
      return sendJson(res, 200, { ok: true, version: VERSION });
    }
    if (method === 'GET' && p === '/.well-known/jwks.json') {
      return sendJson(res, 200, jwks, { 'Cache-Control': 'public, max-age=300' });
    }
    if (method === 'GET' && p === '/api/public-key.pem') {
      res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': 'application/x-pem-file', 'X-Key-Id': key.kid, 'Cache-Control': 'public, max-age=300' });
      res.end(key.publicKeyPem);
      return;
    }
    if (method === 'GET' && statics[p]) {
      const f = statics[p];
      res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': f.type, 'Cache-Control': 'no-cache', 'Content-Length': f.body.length });
      res.end(f.body);
      return;
    }

    // ---------- OtonomMCP machine API (bearer) ----------
    if (p === '/api/status' && method === 'GET') {
      requireBearer(req);
      return sendJson(res, 200, {
        status: 'ok',
        version: VERSION,
        time: new Date(cfg.now()).toISOString(),
        uptimeSeconds: Math.floor((cfg.now() - startedAt) / 1000),
        issuer: cfg.issuer,
        audience: cfg.audience,
        kid: key.kid,
        setupRequired: auth.needsSetup(),
        pending: requests.pendingCounts(),
      });
    }
    if (p === '/api/approval-requests' && method === 'POST') {
      requireBearer(req);
      return sendJson(res, 201, requests.createApproval(await readJson(req, cfg.maxBodyBytes)));
    }
    if ((m = new RegExp(`^/api/approval-requests/${UUID_PATH}$`).exec(p)) && method === 'GET') {
      requireBearer(req);
      return sendJson(res, 200, requests.approvalStatus(m[1]));
    }
    if (p === '/api/decision-requests' && method === 'POST') {
      requireBearer(req);
      return sendJson(res, 201, requests.createDecision(await readJson(req, cfg.maxBodyBytes)));
    }
    if ((m = new RegExp(`^/api/decision-requests/${UUID_PATH}$`).exec(p)) && method === 'GET') {
      requireBearer(req);
      return sendJson(res, 200, requests.decisionStatus(m[1]));
    }

    // ---------- live instructions: machine side (bearer) ----------
    if ((m = /^\/api\/runs\/([^/]+)\/instruction-channel$/.exec(p))) {
      requireBearer(req);
      if (method === 'PUT') return sendJson(res, 200, instructions.putChannel(m[1], await readJson(req, cfg.maxBodyBytes)));
      if (method === 'DELETE') return sendJson(res, 200, instructions.closeChannel(m[1]));
      throw new HttpError(405, 'METHOD_NOT_ALLOWED', 'Method not allowed');
    }
    if ((m = /^\/api\/runs\/([^/]+)\/instructions$/.exec(p))) {
      requireBearer(req);
      if (method === 'GET') return sendJson(res, 200, instructions.pending(m[1], url.searchParams.get('status')));
      throw new HttpError(405, 'METHOD_NOT_ALLOWED', 'Method not allowed');
    }
    if ((m = /^\/api\/runs\/([^/]+)\/instructions\/([^/]+)\/ack$/.exec(p))) {
      requireBearer(req);
      if (method === 'POST') return sendJson(res, 200, instructions.ack(m[1], m[2], await readJson(req, cfg.maxBodyBytes)));
      throw new HttpError(405, 'METHOD_NOT_ALLOWED', 'Method not allowed');
    }

    // ---------- run monitor (OtonomMCP -> IdP, informational only) ----------
    if ((m = /^\/api\/runs\/([^/]+)(\/events)?$/.exec(p))) {
      requireBearer(req);
      const runId = m[1];
      if (!m[2] && method === 'PUT') return sendJson(res, 200, runs.putSnapshot(runId, await readJson(req, cfg.maxBodyBytes)));
      if (m[2] && method === 'POST') return sendJson(res, 200, runs.appendEvents(runId, await readJson(req, cfg.maxBodyBytes)));
      throw new HttpError(405, 'METHOD_NOT_ALLOWED', 'Method not allowed');
    }

    // ---------- browser UI API ----------
    if (p === '/api/ui/state' && method === 'GET') {
      flowHash(req, res);
      const s = session(req);
      return sendJson(res, 200, {
        needsSetup: auth.needsSetup(),
        user: s ? { username: s.user.username, displayName: s.user.display_name, role: s.user.role } : null,
        csrfToken: s?.csrf ?? null,
      });
    }
    if (p === '/api/setup/options' && method === 'POST') {
      rateLimit(req, 'auth', cfg.authRateLimitPerMinute);
      requireSameOrigin(req);
      const b = asObject(await readJson(req, cfg.maxBodyBytes));
      const opts = await auth.setupOptions(flowHash(req, res), String(b.setupCode ?? ''), String(b.username ?? ''), String(b.displayName ?? '').slice(0, 100));
      return sendJson(res, 200, opts);
    }
    if (p === '/api/setup/verify' && method === 'POST') {
      rateLimit(req, 'auth', cfg.authRateLimitPerMinute);
      requireSameOrigin(req);
      const b = asObject(await readJson(req, cfg.maxBodyBytes));
      const user = await auth.setupVerify(flowHash(req, res), b.response as never);
      const csrf = startSession(res, user.id);
      return sendJson(res, 200, { ok: true, user: { username: user.username, role: user.role }, csrfToken: csrf });
    }
    if (p === '/api/auth/login/options' && method === 'POST') {
      rateLimit(req, 'auth', cfg.authRateLimitPerMinute);
      requireSameOrigin(req);
      return sendJson(res, 200, await auth.loginOptions(flowHash(req, res)));
    }
    if (p === '/api/auth/login/verify' && method === 'POST') {
      rateLimit(req, 'auth', cfg.authRateLimitPerMinute);
      requireSameOrigin(req);
      const b = asObject(await readJson(req, cfg.maxBodyBytes));
      const user = await auth.loginVerify(flowHash(req, res), b.response as never);
      const csrf = startSession(res, user.id);
      return sendJson(res, 200, { ok: true, user: { username: user.username, role: user.role }, csrfToken: csrf });
    }
    if (p === '/api/auth/logout' && method === 'POST') {
      requireSession(req, true);
      auth.deleteSession(parseCookies(req.headers.cookie)[SESSION_COOKIE]);
      appendCookie(res, cookie(SESSION_COOKIE, '', { secure: secureCookies, maxAge: 0 }));
      return sendJson(res, 200, { ok: true });
    }
    if (p === '/api/passkeys/options' && method === 'POST') {
      rateLimit(req, 'auth', cfg.authRateLimitPerMinute);
      const s = requireSession(req, true);
      return sendJson(res, 200, await auth.registrationOptions(s.idHash, s.user));
    }
    if (p === '/api/passkeys/verify' && method === 'POST') {
      rateLimit(req, 'auth', cfg.authRateLimitPerMinute);
      const s = requireSession(req, true);
      const b = asObject(await readJson(req, cfg.maxBodyBytes));
      return sendJson(res, 200, { ok: true, credentialId: await auth.registrationVerify(s.idHash, s.user, b.response as never) });
    }
    if (p === '/api/ui/runs' && method === 'GET') {
      requireSession(req, false);
      return sendJson(res, 200, runs.list(url.searchParams.get('active') === '1'));
    }
    if (p === '/api/ui/runs/cleanup' && method === 'POST') {
      const s = requireSession(req, true);
      return sendJson(res, 200, runs.deleteAllDeletable(s.user.id));
    }
    if ((m = /^\/api\/ui\/runs\/([^/]+)$/.exec(p)) && method === 'DELETE') {
      const s = requireSession(req, true);
      return sendJson(res, 200, runs.deleteRun(m[1], s.user.id));
    }
    if ((m = /^\/api\/ui\/runs\/([^/]+)$/.exec(p)) && method === 'GET') {
      requireSession(req, false);
      return sendJson(res, 200, { ...runs.detail(m[1], url.searchParams.get('sinceSeq')), ...instructions.viewForRun(m[1]) });
    }
    // Live instruction: 1) options (validates the form, binds it to a new instructionId + passkey challenge)
    if ((m = /^\/api\/ui\/runs\/([^/]+)\/instructions\/options$/.exec(p)) && method === 'POST') {
      rateLimit(req, 'auth', cfg.authRateLimitPerMinute);
      const s = requireSession(req, true);
      const draft = instructions.validateDraft(m[1], await readJson(req, cfg.maxBodyBytes));
      const instructionId = nodeCrypto.randomUUID();
      const options = await auth.stepUpOptions(s.idHash, s.user, 'instruct', instructionId, draft);
      return sendJson(res, 200, { instructionId, options });
    }
    // 2) submit: the signed content is the draft stored with the challenge, not anything sent now
    if ((m = /^\/api\/ui\/runs\/([^/]+)\/instructions\/([0-9a-fA-F-]{36})$/.exec(p)) && method === 'POST') {
      rateLimit(req, 'auth', cfg.authRateLimitPerMinute);
      const s = requireSession(req, true);
      const b = asObject(await readJson(req, cfg.maxBodyBytes));
      const instructionId = m[2].toLowerCase();
      const { credentialId, payload } = await auth.stepUpVerifyWithPayload(s.idHash, s.user, 'instruct', instructionId, b.assertion);
      const draft = payload as { runId: string; mode: 'NOTE' | 'PAUSE_AND_APPLY' | 'STOP'; text: string; taskId: string | null };
      if (!draft || draft.runId !== m[1]) throw new HttpError(401, 'WEBAUTHN_FAILED', 'Challenge bound to a different run');
      return sendJson(res, 200, instructions.create(instructionId, draft, s.user, credentialId));
    }
    if (p === '/api/ui/pending' && method === 'GET') {
      requireSession(req, false);
      return sendJson(res, 200, requests.listPending());
    }

    if ((m = new RegExp(`^/api/ui/approvals/${UUID_PATH}(/options|/approve|/reject)?$`).exec(p))) {
      const id = m[1].toLowerCase();
      const action = m[2];
      if (!action && method === 'GET') {
        requireSession(req, false);
        return sendJson(res, 200, requests.approvalView(id));
      }
      if (method !== 'POST') throw new HttpError(405, 'METHOD_NOT_ALLOWED', 'Method not allowed');
      rateLimit(req, 'auth', cfg.authRateLimitPerMinute);
      const s = requireSession(req, true);
      if (action === '/options') {
        const view = requests.approvalView(id);
        if (view.status !== 'PENDING') throw new HttpError(409, view.status === 'EXPIRED' ? 'EXPIRED' : 'ALREADY_DECIDED', `request is ${view.status}`);
        return sendJson(res, 200, await auth.stepUpOptions(s.idHash, s.user, 'approve', id));
      }
      const b = asObject(await readJson(req, cfg.maxBodyBytes));
      if (action === '/approve') {
        const view = requests.approvalView(id);
        if (view.status !== 'PENDING') throw new HttpError(409, view.status === 'EXPIRED' ? 'EXPIRED' : 'ALREADY_DECIDED', `request is ${view.status}`);
        const credentialId = await auth.stepUpVerify(s.idHash, s.user, 'approve', id, b.assertion);
        requests.approve(id, s.user, credentialId);
        return sendJson(res, 200, { ok: true, status: 'APPROVED' });
      }
      requests.reject(id, s.user, b.reason);
      return sendJson(res, 200, { ok: true, status: 'REJECTED' });
    }

    if ((m = new RegExp(`^/api/ui/decisions/${UUID_PATH}(/options|/answer)?$`).exec(p))) {
      const id = m[1].toLowerCase();
      const action = m[2];
      if (!action && method === 'GET') {
        requireSession(req, false);
        return sendJson(res, 200, requests.decisionView(id));
      }
      if (method !== 'POST') throw new HttpError(405, 'METHOD_NOT_ALLOWED', 'Method not allowed');
      rateLimit(req, 'auth', cfg.authRateLimitPerMinute);
      const s = requireSession(req, true);
      const view = requests.decisionView(id);
      if (view.status !== 'PENDING') throw new HttpError(409, view.status === 'EXPIRED' ? 'EXPIRED' : 'ALREADY_ANSWERED', `decision is ${view.status}`);
      if (action === '/options') return sendJson(res, 200, await auth.stepUpOptions(s.idHash, s.user, 'decide', id));
      const b = asObject(await readJson(req, cfg.maxBodyBytes));
      const answer = { selectedOptionId: b.selectedOptionId, freeText: b.freeText };
      requests.validateAnswer(id, answer); // reject bad input before burning the passkey challenge
      const credentialId = await auth.stepUpVerify(s.idHash, s.user, 'decide', id, b.assertion);
      requests.answer(id, s.user, credentialId, answer);
      return sendJson(res, 200, { ok: true, status: 'ANSWERED' });
    }

    throw new HttpError(404, 'NOT_FOUND', 'Not found');
  }

  return {
    server,
    db,
    cfg,
    key,
    auth,
    requests,
    runs,
    instructions,
    clientToken,
    setupCode,
    startedAt,
    listen() {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(cfg.port, cfg.host, () => {
          const a = server.address() as AddressInfo;
          resolve({ port: a.port, host: a.address });
        });
      });
    },
    close() {
      return new Promise((resolve) => {
        server.closeAllConnections?.();
        server.close(() => {
          try {
            db.close();
          } catch {
            /* already closed */
          }
          resolve();
        });
      });
    },
  };
}
