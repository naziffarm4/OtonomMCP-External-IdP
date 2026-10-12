import * as path from 'node:path';

export interface IdpConfig {
  host: string;
  port: number;
  dataDir: string;
  issuer: string;
  audience: string;
  rpId: string;
  rpName: string;
  origin: string;
  /** Optional fixed bearer token for OtonomMCP (env IDP_CLIENT_TOKEN). */
  clientToken?: string;
  /** Optional fixed one-time setup code (env IDP_SETUP_CODE). */
  setupCode?: string;
  /** Decision token lifetime in seconds (max 300). */
  tokenTtlSeconds: number;
  /** Max lifetime of an approval request in seconds (contract: 15 min). */
  maxRequestTtlSeconds: number;
  sessionTtlSeconds: number;
  challengeTtlSeconds: number;
  /** Requests per minute per IP on login / WebAuthn endpoints. */
  authRateLimitPerMinute: number;
  apiRateLimitPerMinute: number;
  maxBodyBytes: number;
  /** A non-terminal run with no snapshot/event for this long may be deleted from the UI (IDP_RUN_STALE_MINUTES, default 15). */
  runStaleSeconds: number;
  /** Log to console (disabled in tests). */
  log: (msg: string) => void;
  now: () => number;
}

function intEnv(env: NodeJS.ProcessEnv, key: string, def: number, min: number, max: number): number {
  const raw = env[key];
  if (raw === undefined || raw === '') return def;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new Error(`${key} must be an integer between ${min} and ${max}`);
  }
  return n;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env, overrides: Partial<IdpConfig> = {}): IdpConfig {
  const port = intEnv(env, 'IDP_PORT', 7443, 0, 65535);
  const cfg: IdpConfig = {
    host: env.IDP_HOST || '127.0.0.1',
    port,
    dataDir: path.resolve(env.IDP_DATA_DIR || './data'),
    issuer: env.IDP_ISSUER || 'otonommcp-external-idp',
    audience: env.IDP_AUDIENCE || 'otonommcp',
    rpId: env.IDP_RP_ID || 'localhost',
    rpName: env.IDP_RP_NAME || 'OtonomMCP External IdP',
    origin: (env.IDP_ORIGIN || `http://localhost:${port || 7443}`).replace(/\/+$/, ''),
    clientToken: env.IDP_CLIENT_TOKEN || undefined,
    setupCode: env.IDP_SETUP_CODE || undefined,
    tokenTtlSeconds: intEnv(env, 'IDP_TOKEN_TTL_SECONDS', 300, 30, 300),
    maxRequestTtlSeconds: 15 * 60,
    sessionTtlSeconds: intEnv(env, 'IDP_SESSION_TTL_SECONDS', 8 * 3600, 60, 7 * 24 * 3600),
    challengeTtlSeconds: 300,
    authRateLimitPerMinute: intEnv(env, 'IDP_AUTH_RATE_LIMIT', 20, 1, 10000),
    apiRateLimitPerMinute: intEnv(env, 'IDP_API_RATE_LIMIT', 300, 1, 100000),
    maxBodyBytes: 64 * 1024,
    runStaleSeconds: intEnv(env, 'IDP_RUN_STALE_MINUTES', 15, 1, 7 * 24 * 60) * 60,
    log: (msg: string) => console.log(`[idp] ${msg}`),
    now: () => Date.now(),
    ...overrides,
  };
  if (cfg.clientToken !== undefined && cfg.clientToken.length < 32) {
    throw new Error('IDP_CLIENT_TOKEN must be at least 32 characters');
  }
  let originUrl: URL;
  try {
    originUrl = new URL(cfg.origin);
  } catch {
    throw new Error('IDP_ORIGIN must be an absolute URL such as http://localhost:7443');
  }
  if (originUrl.hostname !== cfg.rpId && !originUrl.hostname.endsWith(`.${cfg.rpId}`)) {
    throw new Error(`IDP_RP_ID (${cfg.rpId}) must equal or be a suffix of the IDP_ORIGIN host (${originUrl.hostname})`);
  }
  return cfg;
}
