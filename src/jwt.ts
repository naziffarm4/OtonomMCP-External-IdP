import * as crypto from 'node:crypto';
import type { SigningKey } from './keys';

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');

/** Compact JWS, ES256, raw r||s (IEEE-P1363) signature per RFC 7518 §3.4. */
export function signEs256(claims: object, key: SigningKey): string {
  const input = `${b64({ alg: 'ES256', typ: 'JWT', kid: key.kid })}.${b64(claims)}`;
  const sig = crypto.sign('sha256', Buffer.from(input), { key: key.privateKey, dsaEncoding: 'ieee-p1363' });
  return `${input}.${sig.toString('base64url')}`;
}

export interface VerifyOptions {
  issuer: string;
  audience: string;
  now: number;
  clockSkewSeconds?: number;
}

/** Strict verifier: ES256 only, kid must match, iss/aud/exp/nbf/iat/jti required. */
export function verifyEs256(token: string, publicKey: crypto.KeyObject | string, kid: string, opts: VerifyOptions): Record<string, any> {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('malformed token');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  if (header.alg !== 'ES256') throw new Error(`alg ${header.alg} not allowed`);
  if (header.kid !== kid) throw new Error('unknown kid');
  const sig = Buffer.from(parts[2], 'base64url');
  if (sig.length !== 64) throw new Error('bad signature length');
  const key = typeof publicKey === 'string' ? crypto.createPublicKey(publicKey) : publicKey;
  if (!crypto.verify('sha256', Buffer.from(`${parts[0]}.${parts[1]}`), { key, dsaEncoding: 'ieee-p1363' }, sig)) {
    throw new Error('signature invalid');
  }
  const p = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  const skew = opts.clockSkewSeconds ?? 30;
  const nowS = Math.floor(opts.now / 1000);
  if (p.iss !== opts.issuer) throw new Error('issuer mismatch');
  if (p.aud !== opts.audience) throw new Error('audience mismatch');
  if (typeof p.jti !== 'string' || !p.jti) throw new Error('jti missing');
  if (typeof p.exp !== 'number' || p.exp + skew < nowS) throw new Error('expired');
  if (typeof p.nbf !== 'number' || p.nbf - skew > nowS) throw new Error('not yet valid');
  if (typeof p.iat !== 'number' || p.iat - skew > nowS) throw new Error('issued in the future');
  return p;
}
