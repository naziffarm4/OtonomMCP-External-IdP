/**
 * Software WebAuthn authenticator for tests and the contract check.
 * Produces real WebAuthn-format responses (CBOR attestationObject with fmt 'none',
 * authenticatorData with rpIdHash/flags/counter/attested credential data, COSE ES256 key,
 * clientDataJSON with type/challenge/origin, DER ECDSA assertion signatures) so that
 * @simplewebauthn/server's real verification code runs against them.
 * NOT used by the server at runtime.
 */
import * as crypto from 'node:crypto';

type Cbor = number | string | Buffer | Uint8Array | Cbor[] | Map<Cbor, Cbor> | { [k: string]: Cbor } | boolean;

function head(major: number, n: number): Buffer {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) { const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(n, 1); return b; }
  const b = Buffer.alloc(5); b[0] = (major << 5) | 26; b.writeUInt32BE(n, 1); return b;
}

export function cborEncode(v: Cbor): Buffer {
  if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === 'boolean') return Buffer.from([v ? 0xf5 : 0xf4]);
  if (typeof v === 'string') { const b = Buffer.from(v, 'utf8'); return Buffer.concat([head(3, b.length), b]); }
  if (Buffer.isBuffer(v) || v instanceof Uint8Array) return Buffer.concat([head(2, v.length), Buffer.from(v)]);
  if (Array.isArray(v)) return Buffer.concat([head(4, v.length), ...v.map(cborEncode)]);
  const entries: [Cbor, Cbor][] = v instanceof Map ? [...v.entries()] : Object.entries(v);
  return Buffer.concat([head(5, entries.length), ...entries.flatMap(([k, val]) => [cborEncode(k), cborEncode(val)])]);
}

export interface SoftAuthenticatorOptions {
  origin: string;
  rpId: string;
  /** Set false to simulate an authenticator that skips user verification. */
  userVerified?: boolean;
  userPresent?: boolean;
  /** Counter increment per assertion (0 = authenticator without counter). */
  counterStep?: number;
}

export class SoftAuthenticator {
  readonly credentialId = crypto.randomBytes(32);
  private readonly keys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  counter = 0;
  userHandle?: string;
  constructor(public opts: SoftAuthenticatorOptions) {}

  get id(): string { return this.credentialId.toString('base64url'); }

  private flags(attested: boolean): number {
    let f = 0;
    if (this.opts.userPresent !== false) f |= 0x01;
    if (this.opts.userVerified !== false) f |= 0x04;
    if (attested) f |= 0x40;
    return f;
  }

  private cosePublicKey(): Buffer {
    const jwk = this.keys.publicKey.export({ format: 'jwk' }) as { x: string; y: string };
    return cborEncode(new Map<Cbor, Cbor>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
  }

  private authData(attested: boolean, rpId = this.opts.rpId): Buffer {
    const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(this.counter >>> 0, 0);
    const parts: Buffer[] = [rpIdHash, Buffer.from([this.flags(attested)]), counter];
    if (attested) {
      const len = Buffer.alloc(2);
      len.writeUInt16BE(this.credentialId.length, 0);
      parts.push(Buffer.alloc(16), len, this.credentialId, this.cosePublicKey());
    }
    return Buffer.concat(parts);
  }

  private clientData(type: string, challenge: string, origin = this.opts.origin): Buffer {
    return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
  }

  /** navigator.credentials.create() equivalent; returns RegistrationResponseJSON. */
  register(options: { challenge: string; rp?: { id?: string }; user?: { id: string } }, override: { origin?: string; rpId?: string } = {}) {
    this.userHandle = options.user?.id;
    const clientDataJSON = this.clientData('webauthn.create', options.challenge, override.origin);
    const attestationObject = cborEncode({ fmt: 'none', attStmt: new Map(), authData: this.authData(true, override.rpId) } as never);
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key' as const,
      response: {
        clientDataJSON: clientDataJSON.toString('base64url'),
        attestationObject: attestationObject.toString('base64url'),
        transports: ['internal' as const],
      },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform' as const,
    };
  }

  /** navigator.credentials.get() equivalent; returns AuthenticationResponseJSON. */
  authenticate(options: { challenge: string }, override: { origin?: string; rpId?: string; counter?: number } = {}) {
    this.counter = override.counter ?? this.counter + (this.opts.counterStep ?? 1);
    const authenticatorData = this.authData(false, override.rpId);
    const clientDataJSON = this.clientData('webauthn.get', options.challenge, override.origin);
    const signed = Buffer.concat([authenticatorData, crypto.createHash('sha256').update(clientDataJSON).digest()]);
    const signature = crypto.sign('sha256', signed, this.keys.privateKey); // DER, as real authenticators do
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key' as const,
      response: {
        clientDataJSON: clientDataJSON.toString('base64url'),
        authenticatorData: authenticatorData.toString('base64url'),
        signature: signature.toString('base64url'),
        userHandle: this.userHandle,
      },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform' as const,
    };
  }
}
