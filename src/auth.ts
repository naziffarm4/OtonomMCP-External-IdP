import * as crypto from 'node:crypto';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
  type AuthenticatorTransport,
} from '@simplewebauthn/server';
import type { IdpConfig } from './config';
import { audit, deleteMeta, getMeta, setMeta, transaction, type Db } from './db';
import { safeEqual, sha256Hex } from './keys';
import { HttpError, bad } from './validation';

export type ChallengePurpose = 'setup' | 'register' | 'login' | 'approve' | 'decide' | 'instruct' | 'resume';
export type StepUpPurpose = 'approve' | 'decide' | 'instruct' | 'resume';

export interface User {
  id: string;
  username: string;
  display_name: string;
  role: 'PRODUCT_OWNER';
  webauthn_user_id: string;
  disabled: number;
}

interface CredentialRow {
  id: string;
  user_id: string;
  public_key: Uint8Array;
  counter: number;
  transports: string | null;
}

interface ChallengeRow {
  id: string;
  challenge: string;
  purpose: ChallengePurpose;
  binding_hash: string;
  user_id: string | null;
  target_id: string | null;
  payload: string | null;
  expires_at: number;
  used_at: number | null;
}

const USERNAME_RE = /^[A-Za-z0-9._@-]{3,64}$/;
const SETUP_HASH_KEY = 'setup_code_hash';

const authFail = (msg = 'WebAuthn verification failed') => new HttpError(401, 'WEBAUTHN_FAILED', msg);

/** Extracts the challenge the authenticator signed from clientDataJSON (verified again by @simplewebauthn). */
export function challengeFromResponse(resp: unknown): string {
  const r = resp as { response?: { clientDataJSON?: unknown } };
  const cdj = r?.response?.clientDataJSON;
  if (typeof cdj !== 'string' || cdj.length > 4096) throw bad('response.clientDataJSON missing');
  try {
    const parsed = JSON.parse(Buffer.from(cdj, 'base64url').toString('utf8'));
    if (typeof parsed.challenge !== 'string') throw new Error();
    return parsed.challenge;
  } catch {
    throw bad('response.clientDataJSON malformed');
  }
}

export class AuthService {
  constructor(private readonly db: Db, private readonly cfg: IdpConfig) {}

  // ---------- bootstrap ----------

  needsSetup(): boolean {
    const row = this.db.prepare('SELECT COUNT(*) AS n FROM users').get() as { n: number };
    return row.n === 0;
  }

  /** On first run, arms a one-time setup code (env IDP_SETUP_CODE or random). Returns the code if newly generated. */
  ensureSetupCode(): string | undefined {
    if (!this.needsSetup()) {
      deleteMeta(this.db, SETUP_HASH_KEY);
      return undefined;
    }
    if (this.cfg.setupCode) {
      if (this.cfg.setupCode.length < 8) throw new Error('IDP_SETUP_CODE must be at least 8 characters');
      setMeta(this.db, SETUP_HASH_KEY, sha256Hex(this.cfg.setupCode));
      this.cfg.log('First run: create the owner account with the setup code from IDP_SETUP_CODE.');
      return undefined;
    }
    const code = Array.from({ length: 3 }, () => crypto.randomBytes(3).toString('hex').toUpperCase()).join('-');
    setMeta(this.db, SETUP_HASH_KEY, sha256Hex(code));
    this.cfg.log(`First run: one-time setup code = ${code}  (open ${this.cfg.origin}/ and choose "İlk kurulum")`);
    return code;
  }

  // ---------- challenges ----------

  private storeChallenge(challenge: string, purpose: ChallengePurpose, bindingHash: string, extra: { userId?: string; targetId?: string; payload?: unknown } = {}): void {
    const now = this.cfg.now();
    this.db.prepare('DELETE FROM webauthn_challenges WHERE expires_at < ? OR used_at IS NOT NULL AND used_at < ?').run(now, now - 3600_000);
    this.db
      .prepare(
        `INSERT INTO webauthn_challenges (id, challenge, purpose, binding_hash, user_id, target_id, payload, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(crypto.randomUUID(), challenge, purpose, bindingHash, extra.userId ?? null, extra.targetId ?? null,
        extra.payload === undefined ? null : JSON.stringify(extra.payload), now, now + this.cfg.challengeTtlSeconds * 1000);
  }

  /** Atomically consumes a single-use challenge that must match purpose, binding (cookie/session) and target. */
  private consumeChallenge(challenge: string, purpose: ChallengePurpose, bindingHash: string, targetId?: string, userId?: string): ChallengeRow {
    // Burn the challenge in its own committed transaction, then judge it: a mismatching
    // or failed attempt can never be retried with the same challenge.
    const { row, error } = transaction(this.db, () => {
      const r = this.db.prepare('SELECT * FROM webauthn_challenges WHERE challenge = ?').get(challenge) as ChallengeRow | undefined;
      if (!r) return { row: undefined, error: 'Unknown challenge' };
      if (r.used_at !== null) return { row: r, error: 'Challenge already used' };
      this.db.prepare('UPDATE webauthn_challenges SET used_at = ? WHERE id = ? AND used_at IS NULL').run(this.cfg.now(), r.id);
      return { row: r, error: undefined as string | undefined };
    });
    if (error || !row) throw authFail(error);
    if (row.expires_at < this.cfg.now()) throw authFail('Challenge expired');
    if (row.purpose !== purpose) throw authFail('Challenge purpose mismatch');
    if (!safeEqual(row.binding_hash, bindingHash)) throw authFail('Challenge not bound to this browser session');
    if ((row.target_id ?? undefined) !== targetId) throw authFail('Challenge bound to a different request');
    if (userId !== undefined && row.user_id !== userId) throw authFail('Challenge bound to a different user');
    return row;
  }

  // ---------- registration ----------

  async setupOptions(flowHash: string, setupCode: string, username: string, displayName: string) {
    if (!this.needsSetup()) throw new HttpError(409, 'ALREADY_SET_UP', 'Setup already completed');
    const stored = getMeta(this.db, SETUP_HASH_KEY);
    if (!stored || typeof setupCode !== 'string' || !safeEqual(stored, sha256Hex(setupCode.trim()))) {
      audit(this.db, this.cfg.now(), 'anonymous', 'setup.code_rejected');
      throw new HttpError(403, 'BAD_SETUP_CODE', 'Invalid setup code');
    }
    if (!USERNAME_RE.test(username)) throw bad('username must be 3-64 chars [A-Za-z0-9._@-]');
    const webauthnUserId = crypto.randomBytes(32);
    const options = await generateRegistrationOptions({
      rpName: this.cfg.rpName,
      rpID: this.cfg.rpId,
      userName: username,
      userDisplayName: displayName || username,
      userID: webauthnUserId,
      attestationType: 'none',
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      supportedAlgorithmIDs: [-7, -257],
      timeout: this.cfg.challengeTtlSeconds * 1000,
    });
    this.storeChallenge(options.challenge, 'setup', flowHash, {
      payload: { username, displayName: displayName || username, webauthnUserId: webauthnUserId.toString('base64url') },
    });
    return options;
  }

  async registrationOptions(sessionHash: string, user: User) {
    const creds = this.credentialsFor(user.id);
    const options = await generateRegistrationOptions({
      rpName: this.cfg.rpName,
      rpID: this.cfg.rpId,
      userName: user.username,
      userDisplayName: user.display_name,
      userID: Buffer.from(user.webauthn_user_id, 'base64url'),
      attestationType: 'none',
      excludeCredentials: creds.map((c) => ({ id: c.id, transports: this.transports(c) })),
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      supportedAlgorithmIDs: [-7, -257],
      timeout: this.cfg.challengeTtlSeconds * 1000,
    });
    this.storeChallenge(options.challenge, 'register', sessionHash, { userId: user.id });
    return options;
  }

  private async verifyRegistration(response: RegistrationResponseJSON, challenge: string) {
    let result;
    try {
      result = await verifyRegistrationResponse({
        response,
        expectedChallenge: challenge,
        expectedOrigin: this.cfg.origin,
        expectedRPID: this.cfg.rpId,
        requireUserVerification: true,
        supportedAlgorithmIDs: [-7, -257],
      });
    } catch (e) {
      throw authFail(`Registration rejected: ${(e as Error).message}`);
    }
    if (!result.verified || !result.registrationInfo.userVerified) throw authFail('Registration not verified (user verification required)');
    return result.registrationInfo;
  }

  private insertCredential(userId: string, info: Awaited<ReturnType<AuthService['verifyRegistration']>>): void {
    const exists = this.db.prepare('SELECT 1 FROM webauthn_credentials WHERE id = ?').get(info.credential.id);
    if (exists) throw new HttpError(409, 'CREDENTIAL_EXISTS', 'Credential already registered');
    this.db
      .prepare(
        `INSERT INTO webauthn_credentials (id, user_id, public_key, counter, transports, device_type, backed_up, aaguid, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(info.credential.id, userId, Buffer.from(info.credential.publicKey), info.credential.counter,
        JSON.stringify(info.credential.transports ?? []), info.credentialDeviceType, info.credentialBackedUp ? 1 : 0, info.aaguid, this.cfg.now());
  }

  async setupVerify(flowHash: string, response: RegistrationResponseJSON): Promise<User> {
    const ch = this.consumeChallenge(challengeFromResponse(response), 'setup', flowHash);
    const info = await this.verifyRegistration(response, ch.challenge);
    const p = JSON.parse(ch.payload ?? '{}') as { username: string; displayName: string; webauthnUserId: string };
    return transaction(this.db, () => {
      if (!this.needsSetup() || !getMeta(this.db, SETUP_HASH_KEY)) throw new HttpError(409, 'ALREADY_SET_UP', 'Setup already completed');
      const id = crypto.randomUUID();
      this.db
        .prepare('INSERT INTO users (id, username, display_name, role, webauthn_user_id, created_at) VALUES (?, ?, ?, ?, ?, ?)')
        .run(id, p.username, p.displayName, 'PRODUCT_OWNER', p.webauthnUserId, this.cfg.now());
      this.insertCredential(id, info);
      deleteMeta(this.db, SETUP_HASH_KEY);
      audit(this.db, this.cfg.now(), id, 'setup.completed', null, { username: p.username, credentialId: info.credential.id });
      return this.userById(id)!;
    });
  }

  async registrationVerify(sessionHash: string, user: User, response: RegistrationResponseJSON): Promise<string> {
    const ch = this.consumeChallenge(challengeFromResponse(response), 'register', sessionHash, undefined, user.id);
    const info = await this.verifyRegistration(response, ch.challenge);
    transaction(this.db, () => {
      this.insertCredential(user.id, info);
      audit(this.db, this.cfg.now(), user.id, 'passkey.added', null, { credentialId: info.credential.id });
    });
    return info.credential.id;
  }

  // ---------- authentication ----------

  async loginOptions(flowHash: string) {
    const options = await generateAuthenticationOptions({
      rpID: this.cfg.rpId,
      userVerification: 'required',
      timeout: this.cfg.challengeTtlSeconds * 1000,
    });
    this.storeChallenge(options.challenge, 'login', flowHash);
    return options;
  }

  async loginVerify(flowHash: string, response: AuthenticationResponseJSON): Promise<User> {
    const ch = this.consumeChallenge(challengeFromResponse(response), 'login', flowHash);
    const cred = this.credentialById(response?.id);
    const user = this.userById(cred.user_id);
    if (!user || user.disabled) throw authFail('Account disabled');
    await this.verifyAssertion(cred, response, ch.challenge);
    audit(this.db, this.cfg.now(), user.id, 'login', null, { credentialId: cred.id });
    return user;
  }

  /** Step-up options for approving/answering one specific request (challenge bound to session + target). */
  async stepUpOptions(sessionHash: string, user: User, purpose: StepUpPurpose, targetId: string, payload?: unknown) {
    const creds = this.credentialsFor(user.id);
    if (creds.length === 0) throw new HttpError(403, 'NO_PASSKEY', 'No passkey registered');
    const options = await generateAuthenticationOptions({
      rpID: this.cfg.rpId,
      userVerification: 'required',
      allowCredentials: creds.map((c) => ({ id: c.id, transports: this.transports(c) })),
      timeout: this.cfg.challengeTtlSeconds * 1000,
    });
    this.storeChallenge(options.challenge, purpose, sessionHash, { userId: user.id, targetId, payload });
    return options;
  }

  /** Verifies a fresh UV assertion bound to (session, user, purpose, target). Returns the credential id used. */
  async stepUpVerify(sessionHash: string, user: User, purpose: StepUpPurpose, targetId: string, response: unknown): Promise<string> {
    return (await this.stepUpVerifyWithPayload(sessionHash, user, purpose, targetId, response)).credentialId;
  }

  /** Like stepUpVerify, also returns the payload that was bound to the challenge when the options were issued. */
  async stepUpVerifyWithPayload(sessionHash: string, user: User, purpose: StepUpPurpose, targetId: string, response: unknown): Promise<{ credentialId: string; payload: unknown }> {
    if (!response || typeof response !== 'object') throw new HttpError(401, 'ASSERTION_REQUIRED', 'A fresh passkey assertion is required');
    const resp = response as AuthenticationResponseJSON;
    const ch = this.consumeChallenge(challengeFromResponse(resp), purpose, sessionHash, targetId, user.id);
    const cred = this.credentialById(resp.id);
    if (cred.user_id !== user.id) throw authFail('Passkey belongs to another user');
    await this.verifyAssertion(cred, resp, ch.challenge);
    return { credentialId: cred.id, payload: ch.payload ? JSON.parse(ch.payload) : undefined };
  }

  private async verifyAssertion(cred: CredentialRow, response: AuthenticationResponseJSON, challenge: string): Promise<void> {
    let result;
    try {
      result = await verifyAuthenticationResponse({
        response,
        expectedChallenge: challenge,
        expectedOrigin: this.cfg.origin,
        expectedRPID: this.cfg.rpId,
        requireUserVerification: true,
        credential: { id: cred.id, publicKey: new Uint8Array(cred.public_key), counter: cred.counter, transports: this.transports(cred) },
      });
    } catch (e) {
      audit(this.db, this.cfg.now(), cred.user_id, 'webauthn.rejected', null, { credentialId: cred.id, reason: (e as Error).message });
      throw authFail(`Assertion rejected: ${(e as Error).message}`);
    }
    if (!result.verified || !result.authenticationInfo.userVerified) throw authFail('User verification required');
    const newCounter = result.authenticationInfo.newCounter;
    // Compare-and-set so two concurrent assertions can't both pass with the same counter.
    const upd = this.db
      .prepare('UPDATE webauthn_credentials SET counter = ?, last_used_at = ? WHERE id = ? AND counter = ?')
      .run(newCounter, this.cfg.now(), cred.id, cred.counter);
    if (upd.changes !== 1) throw authFail('Concurrent use of passkey detected');
  }

  private transports(c: CredentialRow): AuthenticatorTransport[] | undefined {
    try {
      const t = JSON.parse(c.transports ?? '[]');
      return Array.isArray(t) && t.length ? t : undefined;
    } catch {
      return undefined;
    }
  }

  private credentialById(id: unknown): CredentialRow {
    if (typeof id !== 'string' || id.length > 1024) throw authFail('Unknown passkey');
    const row = this.db.prepare('SELECT * FROM webauthn_credentials WHERE id = ?').get(id) as CredentialRow | undefined;
    if (!row) throw authFail('Unknown passkey');
    return row;
  }

  credentialsFor(userId: string): CredentialRow[] {
    return this.db.prepare('SELECT * FROM webauthn_credentials WHERE user_id = ?').all(userId) as unknown as CredentialRow[];
  }

  userById(id: string): User | undefined {
    return this.db.prepare('SELECT * FROM users WHERE id = ?').get(id) as User | undefined;
  }

  // ---------- sessions ----------

  createSession(userId: string): { cookie: string; csrf: string } {
    const cookie = crypto.randomBytes(32).toString('base64url');
    const csrf = crypto.randomBytes(32).toString('base64url');
    const now = this.cfg.now();
    this.db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now);
    this.db
      .prepare('INSERT INTO sessions (id_hash, user_id, csrf_token, created_at, expires_at) VALUES (?, ?, ?, ?, ?)')
      .run(sha256Hex(cookie), userId, csrf, now, now + this.cfg.sessionTtlSeconds * 1000);
    return { cookie, csrf };
  }

  getSession(cookie: string | undefined): { user: User; csrf: string; idHash: string } | undefined {
    if (!cookie || cookie.length > 128) return undefined;
    const idHash = sha256Hex(cookie);
    const row = this.db.prepare('SELECT * FROM sessions WHERE id_hash = ?').get(idHash) as
      | { user_id: string; csrf_token: string; expires_at: number }
      | undefined;
    if (!row || row.expires_at < this.cfg.now()) return undefined;
    const user = this.userById(row.user_id);
    if (!user || user.disabled) return undefined;
    return { user, csrf: row.csrf_token, idHash };
  }

  deleteSession(cookie: string | undefined): void {
    if (cookie) this.db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(sha256Hex(cookie));
  }
}
