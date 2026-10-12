import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Db } from './db';

export interface SigningKey {
  kid: string;
  alg: 'ES256';
  privateKey: crypto.KeyObject;
  publicKey: crypto.KeyObject;
  publicKeyPem: string;
  publicJwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string; kid: string; alg: 'ES256'; use: 'sig' };
}

export const PRIVATE_KEY_FILE = 'signing-key.pem';
export const PUBLIC_KEY_FILE = 'public-key.pem';
export const CLIENT_TOKEN_FILE = 'client-token.txt';

/** Writes a secret file readable only by the current user (0600 on POSIX; on Windows it inherits the user-profile ACL). */
export function writeSecretFile(file: string, contents: string): void {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const fd = fs.openSync(file, 'wx', 0o600); // never silently overwrite an existing secret
  try {
    fs.writeSync(fd, contents);
  } finally {
    fs.closeSync(fd);
  }
  try {
    fs.chmodSync(file, 0o600);
  } catch {
    /* best effort on Windows */
  }
}

/** RFC 7638 JWK thumbprint (base64url SHA-256), used as kid. */
export function jwkThumbprint(jwk: { crv: string; kty: string; x: string; y: string }): string {
  return crypto.createHash('sha256').update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })).digest('base64url');
}

function buildKey(privateKey: crypto.KeyObject): SigningKey {
  if (privateKey.asymmetricKeyType !== 'ec' || privateKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    throw new Error('Signing key must be an EC P-256 key');
  }
  const publicKey = crypto.createPublicKey(privateKey);
  const jwk = publicKey.export({ format: 'jwk' }) as { kty: string; crv: string; x: string; y: string };
  const kid = jwkThumbprint(jwk);
  return {
    kid,
    alg: 'ES256',
    privateKey,
    publicKey,
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    publicJwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, kid, alg: 'ES256', use: 'sig' },
  };
}

/** Loads the persistent ES256 key, generating it on first start. The private key is never logged. */
export function loadOrCreateSigningKey(db: Db, dataDir: string, now: number, log: (m: string) => void): SigningKey {
  const privFile = path.join(dataDir, PRIVATE_KEY_FILE);
  const pubFile = path.join(dataDir, PUBLIC_KEY_FILE);
  let key: SigningKey;
  if (fs.existsSync(privFile)) {
    key = buildKey(crypto.createPrivateKey(fs.readFileSync(privFile, 'utf8')));
  } else {
    const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    writeSecretFile(privFile, privateKey.export({ type: 'pkcs8', format: 'pem' }).toString());
    key = buildKey(privateKey);
    log(`Generated new ES256 signing key (kid ${key.kid}).`);
  }
  if (!fs.existsSync(pubFile) || fs.readFileSync(pubFile, 'utf8') !== key.publicKeyPem) {
    fs.writeFileSync(pubFile, key.publicKeyPem, { mode: 0o644 });
  }
  db.prepare('UPDATE signing_keys SET active = 0 WHERE kid != ?').run(key.kid);
  db.prepare(
    `INSERT INTO signing_keys (kid, alg, public_key_pem, private_key_file, created_at, active)
     VALUES (?, 'ES256', ?, ?, ?, 1) ON CONFLICT(kid) DO UPDATE SET active = 1`,
  ).run(key.kid, key.publicKeyPem, PRIVATE_KEY_FILE, now);
  return key;
}

/** Bearer token OtonomMCP must send. Env wins; otherwise generated once and persisted in the data dir. */
export function loadOrCreateClientToken(dataDir: string, envToken: string | undefined, log: (m: string) => void): string {
  if (envToken) return envToken;
  const file = path.join(dataDir, CLIENT_TOKEN_FILE);
  if (fs.existsSync(file)) {
    const t = fs.readFileSync(file, 'utf8').trim();
    if (t.length >= 32) return t;
    throw new Error(`${file} is corrupt (token shorter than 32 chars); delete it to regenerate`);
  }
  const token = crypto.randomBytes(32).toString('base64url');
  writeSecretFile(file, `${token}\n`);
  log(`Generated OtonomMCP client token. Copy it into AIDM_IDP_CLIENT_TOKEN from: ${file}`);
  return token;
}

export function sha256Hex(s: string): string {
  return crypto.createHash('sha256').update(s).digest('hex');
}

/** Constant-time comparison (hash first so lengths never leak through timing). */
export function safeEqual(a: string, b: string): boolean {
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}
