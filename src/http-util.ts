import type { IncomingMessage, ServerResponse } from 'node:http';
import { HttpError } from './validation';

export const SECURITY_HEADERS: Record<string, string> = {
  'Content-Security-Policy':
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
    "font-src 'self'; manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
};

export function sendJson(res: ServerResponse, status: number, body: unknown, extraHeaders: Record<string, string | string[]> = {}): void {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Length': Buffer.byteLength(data),
    ...extraHeaders,
  });
  res.end(data);
}

export function sendError(res: ServerResponse, err: unknown, log?: (m: string) => void): void {
  if (err instanceof HttpError) {
    const headers: Record<string, string> = err.status === 401 && err.code === 'UNAUTHORIZED' ? { 'WWW-Authenticate': 'Bearer' } : {};
    sendJson(res, err.status, { error: err.code, message: err.message }, headers);
    return;
  }
  log?.(`internal error: ${(err as Error)?.stack ?? String(err)}`);
  sendJson(res, 500, { error: 'INTERNAL', message: 'Internal server error' });
}

/** Reads a JSON body with a hard size cap; requires application/json. */
export function readJson(req: IncomingMessage, maxBytes: number): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const ct = String(req.headers['content-type'] ?? '').toLowerCase();
    if (!ct.startsWith('application/json')) {
      reject(new HttpError(415, 'UNSUPPORTED_MEDIA_TYPE', 'Content-Type must be application/json'));
      req.resume();
      return;
    }
    const declared = Number(req.headers['content-length'] ?? 0);
    if (declared > maxBytes) {
      reject(new HttpError(413, 'PAYLOAD_TOO_LARGE', `Body exceeds ${maxBytes} bytes`));
      req.resume();
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    let failed = false;
    req.on('data', (c: Buffer) => {
      if (failed) return;
      size += c.length;
      if (size > maxBytes) {
        failed = true;
        reject(new HttpError(413, 'PAYLOAD_TOO_LARGE', `Body exceeds ${maxBytes} bytes`));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (failed) return;
      if (size === 0) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new HttpError(400, 'INVALID_JSON', 'Body is not valid JSON'));
      }
    });
    req.on('error', reject);
  });
}

export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k && !(k in out)) out[k] = decodeURIComponent(v);
  }
  return out;
}

export function cookie(name: string, value: string, opts: { maxAge?: number; secure: boolean }): string {
  const parts = [`${name}=${value}`, 'Path=/', 'HttpOnly', 'SameSite=Strict'];
  if (opts.maxAge !== undefined) parts.push(`Max-Age=${opts.maxAge}`);
  if (opts.secure) parts.push('Secure');
  return parts.join('; ');
}

/** Fixed-window in-memory rate limiter keyed by bucket+client. */
export class RateLimiter {
  private hits = new Map<string, { count: number; reset: number }>();
  constructor(private readonly now: () => number) {}
  check(key: string, limit: number, windowMs = 60_000): boolean {
    const t = this.now();
    if (this.hits.size > 10_000) {
      for (const [k, v] of this.hits) if (v.reset <= t) this.hits.delete(k);
    }
    const e = this.hits.get(key);
    if (!e || e.reset <= t) {
      this.hits.set(key, { count: 1, reset: t + windowMs });
      return true;
    }
    e.count += 1;
    return e.count <= limit;
  }
}
