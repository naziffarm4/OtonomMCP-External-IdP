/**
 * Live instructions (contract: idp-instruction-contract.md v1): Nazif -> IdP -> OtonomMCP Director.
 * Each instruction is signed by a passkey step-up bound to its instructionId and delivered as an ES256 token.
 */
import * as crypto from 'node:crypto';
import type { IdpConfig } from './config';
import { audit, transaction, type Db } from './db';
import { signEs256 } from './jwt';
import type { SigningKey } from './keys';
import type { User } from './auth';
import { FINISHED_STATUSES, validateRunId } from './runs';
import * as v from './validation';
import { HttpError } from './validation';

export const INSTRUCTION_OPERATION = 'AUTONOMOUS_INSTRUCTION';
export const MODES = ['NOTE', 'PAUSE_AND_APPLY', 'STOP'] as const;
export type InstructionMode = (typeof MODES)[number];
export type InstructionStatus = 'PENDING_DELIVERY' | 'RECEIVED' | 'APPLIED' | 'REJECTED' | 'EXPIRED';
export const INSTRUCTION_TTL_SECONDS = 15 * 60;
export const MAX_TEXT = 2000;

/** Allowed ack transitions. PENDING_DELIVERY -> REJECTED covers tokens OtonomMCP refuses before accepting delivery. */
const TRANSITIONS: Record<string, InstructionStatus[]> = {
  PENDING_DELIVERY: ['RECEIVED', 'REJECTED'],
  RECEIVED: ['APPLIED', 'REJECTED'],
};

interface ChannelRow {
  run_id: string;
  project_id: string;
  package_id: string;
  revision: number;
  context_fingerprint: string;
  opened_at: number;
  open: number;
  updated_at: number;
  closed_at: number | null;
}

interface InstructionRow {
  instruction_id: string;
  run_id: string;
  mode: InstructionMode;
  text: string;
  task_id: string | null;
  revision: number;
  token: string;
  token_expires_at: number;
  status: InstructionStatus;
  note: string | null;
  created_at: number;
  received_at: number | null;
  finished_at: number | null;
}

export interface InstructionDraft {
  runId: string;
  mode: InstructionMode;
  text: string;
  taskId: string | null;
}

const iso = (ms: number) => new Date(ms).toISOString();

export class InstructionService {
  constructor(private readonly db: Db, private readonly cfg: IdpConfig, private readonly key: SigningKey) {}

  // ---------- channel (bearer) ----------

  putChannel(pathRunId: string, body: unknown): { runId: string; open: true } {
    const runId = validateRunId(pathRunId);
    const o = v.asObject(body);
    v.rejectUnknownKeys(o, ['runId', 'projectId', 'packageId', 'revision', 'contextFingerprint', 'openedAt']);
    if (o.runId !== runId) throw v.bad('runId must equal the path :runId');
    const ch = {
      projectId: v.text(o, 'projectId', 128)!,
      packageId: v.text(o, 'packageId', 128)!,
      revision: v.positiveInt(o, 'revision'),
      contextFingerprint: v.text(o, 'contextFingerprint', 200)!,
      openedAt: v.isoTime(o, 'openedAt'),
    };
    const now = this.cfg.now();
    transaction(this.db, () => {
      this.db
        .prepare(
          `INSERT INTO instruction_channels (run_id, project_id, package_id, revision, context_fingerprint, opened_at, open, updated_at, closed_at)
           VALUES (?, ?, ?, ?, ?, ?, 1, ?, NULL)
           ON CONFLICT(run_id) DO UPDATE SET project_id = excluded.project_id, package_id = excluded.package_id, revision = excluded.revision,
             context_fingerprint = excluded.context_fingerprint, opened_at = excluded.opened_at, open = 1, updated_at = excluded.updated_at, closed_at = NULL`,
        )
        .run(runId, ch.projectId, ch.packageId, ch.revision, ch.contextFingerprint, ch.openedAt, now);
      audit(this.db, now, 'otonommcp', 'instruction_channel.opened', runId, { revision: ch.revision });
    });
    return { runId, open: true };
  }

  closeChannel(pathRunId: string): { runId: string; open: false } {
    const runId = validateRunId(pathRunId);
    const now = this.cfg.now();
    const r = this.db.prepare('UPDATE instruction_channels SET open = 0, closed_at = ?, updated_at = ? WHERE run_id = ?').run(now, now, runId);
    if (r.changes !== 1) throw new HttpError(404, 'NOT_FOUND', 'no instruction channel for this run');
    audit(this.db, now, 'otonommcp', 'instruction_channel.closed', runId);
    return { runId, open: false };
  }

  private channel(runId: string): ChannelRow | undefined {
    return this.db.prepare('SELECT * FROM instruction_channels WHERE run_id = ?').get(runId) as ChannelRow | undefined;
  }

  /** The form is available only with an open channel and a non-terminal run status. */
  canInstruct(runId: string): boolean {
    const ch = this.channel(runId);
    if (!ch || ch.open !== 1) return false;
    const run = this.db.prepare('SELECT status FROM runs WHERE run_id = ?').get(runId) as { status: string } | undefined;
    return !run || !FINISHED_STATUSES.includes(run.status);
  }

  // ---------- creation (session + CSRF + step-up) ----------

  /** Validates the form; returns the draft bound to the passkey challenge. */
  validateDraft(pathRunId: string, body: unknown): InstructionDraft {
    const runId = validateRunId(pathRunId);
    const o = v.asObject(body);
    v.rejectUnknownKeys(o, ['mode', 'text', 'taskId']);
    if (typeof o.mode !== 'string' || !(MODES as readonly string[]).includes(o.mode)) throw v.bad(`mode must be one of ${MODES.join(', ')}`);
    const mode = o.mode as InstructionMode;
    let text = '';
    if (mode === 'STOP') text = v.text(o, 'text', MAX_TEXT, true) ?? '';
    else text = v.text(o, 'text', MAX_TEXT)!;
    const taskId = o.taskId === undefined || o.taskId === null || o.taskId === '' ? null : v.text(o, 'taskId', 128)!;
    if (!this.canInstruct(runId)) throw new HttpError(409, 'CHANNEL_CLOSED', 'this run does not accept instructions (no open channel or run finished)');
    return { runId, mode, text, taskId };
  }

  /** Persists the instruction after the passkey assertion was verified for this instructionId. */
  create(instructionId: string, draft: InstructionDraft, user: User, credentialId: string): { instructionId: string; status: 'PENDING_DELIVERY' } {
    if (!credentialId) throw new HttpError(401, 'ASSERTION_REQUIRED', 'A fresh passkey assertion is required');
    if (user.role !== 'PRODUCT_OWNER') throw new HttpError(403, 'FORBIDDEN', 'Only PRODUCT_OWNER may instruct the Director');
    return transaction(this.db, () => {
      if (!this.canInstruct(draft.runId)) throw new HttpError(409, 'CHANNEL_CLOSED', 'this run does not accept instructions anymore');
      if (this.db.prepare('SELECT 1 FROM instructions WHERE instruction_id = ?').get(instructionId)) throw new HttpError(409, 'DUPLICATE', 'instruction already created');
      const ch = this.channel(draft.runId)!;
      const now = this.cfg.now();
      const iat = Math.floor(now / 1000);
      const exp = iat + INSTRUCTION_TTL_SECONDS;
      const nonce = crypto.randomBytes(24).toString('base64url');
      const jti = crypto.randomUUID();
      const claims = {
        iss: this.cfg.issuer,
        aud: this.cfg.audience,
        sub: user.id,
        preferred_username: user.username,
        actorRole: 'PRODUCT_OWNER',
        nonce,
        jti,
        iat,
        nbf: iat,
        exp,
        instructionId,
        runId: draft.runId,
        projectId: ch.project_id,
        packageId: ch.package_id,
        revision: ch.revision,
        contextFingerprint: ch.context_fingerprint,
        operation: INSTRUCTION_OPERATION,
        mode: draft.mode,
        text: draft.text,
        taskId: draft.taskId,
        amr: ['webauthn'],
        uv: true,
      };
      const token = signEs256(claims, this.key);
      this.db
        .prepare(
          `INSERT INTO instructions (instruction_id, run_id, user_id, credential_id, mode, text, task_id, project_id, package_id, revision,
             context_fingerprint, nonce, token, token_jti, token_expires_at, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_DELIVERY', ?)`,
        )
        .run(instructionId, draft.runId, user.id, credentialId, draft.mode, draft.text, draft.taskId, ch.project_id, ch.package_id, ch.revision,
          ch.context_fingerprint, nonce, token, jti, exp * 1000, now);
      audit(this.db, now, user.id, 'instruction.created', instructionId, { runId: draft.runId, mode: draft.mode, credentialId, jti });
      return { instructionId, status: 'PENDING_DELIVERY' as const };
    });
  }

  // ---------- delivery (bearer) ----------

  expireOverdue(): void {
    const now = this.cfg.now();
    transaction(this.db, () => {
      const rows = this.db.prepare("SELECT instruction_id FROM instructions WHERE status = 'PENDING_DELIVERY' AND token_expires_at <= ?").all(now) as { instruction_id: string }[];
      for (const r of rows) audit(this.db, now, 'system', 'instruction.expired', r.instruction_id);
      this.db.prepare("UPDATE instructions SET status = 'EXPIRED', finished_at = ? WHERE status = 'PENDING_DELIVERY' AND token_expires_at <= ?").run(now, now);
    });
  }

  pending(pathRunId: string, status: string | null): { instructions: { instructionId: string; createdAt: string; mode: string; token: string }[] } {
    const runId = validateRunId(pathRunId);
    if (status !== null && status !== 'PENDING_DELIVERY') throw v.bad("status must be 'PENDING_DELIVERY'");
    this.expireOverdue();
    const rows = this.db
      .prepare("SELECT instruction_id, created_at, mode, token FROM instructions WHERE run_id = ? AND status = 'PENDING_DELIVERY' ORDER BY created_at ASC, rowid ASC LIMIT 20")
      .all(runId) as { instruction_id: string; created_at: number; mode: string; token: string }[];
    return { instructions: rows.map((r) => ({ instructionId: r.instruction_id, createdAt: iso(r.created_at), mode: r.mode, token: r.token })) };
  }

  ack(pathRunId: string, instructionIdRaw: string, body: unknown): { runId: string; instructionId: string; status: InstructionStatus } {
    const runId = validateRunId(pathRunId);
    const instructionId = v.uuid({ instructionId: instructionIdRaw }, 'instructionId');
    const o = v.asObject(body);
    v.rejectUnknownKeys(o, ['status', 'note']);
    const status = o.status;
    if (status !== 'RECEIVED' && status !== 'APPLIED' && status !== 'REJECTED') throw v.bad("status must be 'RECEIVED', 'APPLIED' or 'REJECTED'");
    const note = o.note === undefined || o.note === null ? null : v.text(o, 'note', 1000)!;
    this.expireOverdue();
    return transaction(this.db, () => {
      const r = this.db.prepare('SELECT status, run_id FROM instructions WHERE instruction_id = ?').get(instructionId) as { status: InstructionStatus; run_id: string } | undefined;
      if (!r || r.run_id !== runId) throw new HttpError(404, 'NOT_FOUND', 'instruction not found for this run');
      if (!(TRANSITIONS[r.status] ?? []).includes(status)) throw new HttpError(409, 'INVALID_TRANSITION', `cannot go from ${r.status} to ${status}`);
      const now = this.cfg.now();
      const upd = this.db
        .prepare(
          `UPDATE instructions SET status = ?, note = COALESCE(?, note),
             received_at = CASE WHEN ? = 'RECEIVED' THEN ? ELSE received_at END,
             finished_at = CASE WHEN ? IN ('APPLIED','REJECTED') THEN ? ELSE finished_at END
           WHERE instruction_id = ? AND status = ?`,
        )
        .run(status, note, status, now, status, now, instructionId, r.status);
      if (upd.changes !== 1) throw new HttpError(409, 'INVALID_TRANSITION', 'concurrent update');
      audit(this.db, now, 'otonommcp', `instruction.${status.toLowerCase()}`, instructionId, note ? { note } : undefined);
      return { runId, instructionId, status: status as InstructionStatus };
    });
  }

  // ---------- UI view (no tokens) ----------

  viewForRun(runId: string) {
    this.expireOverdue();
    const ch = this.channel(runId);
    const rows = this.db
      .prepare('SELECT * FROM instructions WHERE run_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 100')
      .all(runId) as unknown as InstructionRow[];
    return {
      instructionChannel: ch ? { open: ch.open === 1, revision: ch.revision, openedAt: iso(ch.opened_at), canInstruct: this.canInstruct(runId) } : { open: false, canInstruct: false },
      instructions: rows.map((r) => ({
        instructionId: r.instruction_id,
        mode: r.mode,
        text: r.text,
        taskId: r.task_id,
        revision: r.revision,
        status: r.status,
        note: r.note,
        createdAt: iso(r.created_at),
        receivedAt: r.received_at ? iso(r.received_at) : null,
        finishedAt: r.finished_at ? iso(r.finished_at) : null,
        expiresAt: iso(r.token_expires_at),
      })),
    };
  }
}
