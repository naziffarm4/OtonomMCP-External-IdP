export class HttpError extends Error {
  constructor(public readonly status: number, public readonly code: string, message: string) {
    super(message);
  }
}

export const bad = (msg: string, code = 'VALIDATION_ERROR') => new HttpError(400, code, msg);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const NONCE_RE = /^[A-Za-z0-9._~+/=-]{16,256}$/;
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/;
const ID_RE = /^[\x21-\x7e]{1,256}$/; // printable ASCII, no spaces

export type Obj = Record<string, unknown>;

export function asObject(v: unknown, what = 'body'): Obj {
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw bad(`${what} must be a JSON object`);
  return v as Obj;
}

export function rejectUnknownKeys(o: Obj, allowed: readonly string[], what = 'body'): void {
  for (const k of Object.keys(o)) {
    if (!allowed.includes(k)) throw bad(`${what}: unknown field '${k}'`);
  }
}

export function uuid(o: Obj, k: string): string {
  const v = o[k];
  if (typeof v !== 'string' || !UUID_RE.test(v)) throw bad(`${k} must be a UUID`);
  return v.toLowerCase();
}

export function ident(o: Obj, k: string, optional = false): string | undefined {
  const v = o[k];
  if (v === undefined || v === null) {
    if (optional) return undefined;
    throw bad(`${k} is required`);
  }
  if (typeof v !== 'string' || !ID_RE.test(v)) throw bad(`${k} must be 1-256 printable ASCII characters without spaces`);
  return v;
}

export function text(o: Obj, k: string, max: number, optional = false, min = 1): string | undefined {
  const v = o[k];
  if (v === undefined || v === null) {
    if (optional) return undefined;
    throw bad(`${k} is required`);
  }
  if (typeof v !== 'string') throw bad(`${k} must be a string`);
  const t = v.trim();
  if (t.length < min || t.length > max) throw bad(`${k} must be ${min}-${max} characters`);
  if (CONTROL_RE.test(v)) throw bad(`${k} contains forbidden control characters`);
  return t;
}

export function nonce(o: Obj): string {
  const v = o.nonce;
  if (typeof v !== 'string' || !NONCE_RE.test(v)) throw bad('nonce must be 16-256 URL-safe characters');
  return v;
}

export function positiveInt(o: Obj, k: string): number {
  const v = o[k];
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 1) throw bad(`${k} must be a positive integer`);
  return v;
}

export function bool(o: Obj, k: string): boolean {
  const v = o[k];
  if (typeof v !== 'boolean') throw bad(`${k} must be a boolean`);
  return v;
}

export function isoTime(o: Obj, k: string): number {
  const v = o[k];
  if (typeof v !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/.test(v)) {
    throw bad(`${k} must be an ISO-8601 timestamp with timezone`);
  }
  const ms = Date.parse(v);
  if (Number.isNaN(ms)) throw bad(`${k} is not a valid date`);
  return ms;
}

/** Validates requestedAt/expiresAt against now: not in the future, not expired, lifetime <= maxTtl. */
export function validateWindow(requestedAt: number, expiresAt: number, now: number, maxTtlSeconds: number): void {
  const skew = 60_000;
  if (requestedAt > now + skew) throw bad('requestedAt is in the future');
  if (requestedAt < now - maxTtlSeconds * 1000) throw bad('requestedAt is too old');
  if (expiresAt <= now) throw bad('expiresAt is already in the past');
  if (expiresAt <= requestedAt) throw bad('expiresAt must be after requestedAt');
  if (expiresAt - requestedAt > maxTtlSeconds * 1000 || expiresAt - now > maxTtlSeconds * 1000 + skew) {
    throw bad(`expiresAt must be at most ${maxTtlSeconds / 60} minutes after requestedAt`);
  }
}

/** summary: a string (<=4000 chars) or an object of up to 40 fields whose values are string/number/boolean or arrays (<=50) of those. Stored as JSON. */
export function summary(o: Obj, k: string, optional: boolean): string | undefined {
  const v = o[k];
  if (v === undefined || v === null) {
    if (optional) return undefined;
    throw bad(`${k} is required`);
  }
  if (typeof v === 'string') {
    text(o, k, 4000);
    return JSON.stringify(v.trim());
  }
  const obj = asObject(v, k);
  const keys = Object.keys(obj);
  if (keys.length === 0 || keys.length > 40) throw bad(`${k} must have 1-40 fields`);
  type Prim = string | number | boolean;
  const prim = (val: unknown, where: string): Prim => {
    if (typeof val === 'string') {
      if (val.length > 2000 || CONTROL_RE.test(val)) throw bad(`${where} is too long or has control characters`);
      return val;
    }
    if (typeof val === 'number' && Number.isFinite(val)) return val;
    if (typeof val === 'boolean') return val;
    throw bad(`${where} must be a string, number, boolean or a flat array of those`);
  };
  const out: Record<string, Prim | Prim[]> = {};
  for (const key of keys) {
    if (key.length > 100 || CONTROL_RE.test(key) || key === '__proto__') throw bad(`${k}: invalid field name`);
    const val = obj[key];
    if (val === null) continue;
    if (Array.isArray(val)) {
      if (val.length > 50) throw bad(`${k}.${key} has too many items`);
      out[key] = val.map((x, i) => prim(x, `${k}.${key}[${i}]`));
    } else out[key] = prim(val, `${k}.${key}`);
  }
  const s = JSON.stringify(out);
  if (s.length > 16_000) throw bad(`${k} is too large`);
  return s;
}
