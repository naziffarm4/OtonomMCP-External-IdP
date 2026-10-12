import * as crypto from 'node:crypto';
import type { IdpConfig } from './config';
import { audit, transaction, type Db } from './db';
import { signEs256 } from './jwt';
import type { SigningKey } from './keys';
import type { User } from './auth';
import * as v from './validation';
import { HttpError } from './validation';

export type ApprovalStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED';
export type DecisionStatus = 'PENDING' | 'ANSWERED' | 'EXPIRED';

interface ApprovalRow {
  request_id: string;
  project_id: string;
  package_id: string;
  revision: number;
  context_fingerprint: string;
  spec_fingerprint: string;
  director_session_id: string | null;
  task_id: string | null;
  operation: string;
  nonce: string;
  summary: string;
  requested_at: number;
  expires_at: number;
  received_at: number;
  status: ApprovalStatus;
}

interface DecisionRow {
  decision_id: string;
  project_id: string;
  run_id: string;
  task_id: string;
  context_fingerprint: string;
  question: string;
  options: string;
  allow_free_text: number;
  recommended_option_id: string | null;
  nonce: string;
  summary: string | null;
  requested_at: number;
  expires_at: number;
  received_at: number;
  status: DecisionStatus;
}

export interface DecisionOption {
  id: string;
  label: string;
  description?: string;
}

const APPROVAL_FIELDS = [
  'requestId', 'projectId', 'packageId', 'revision', 'contextFingerprint', 'specFingerprint', 'directorSessionId',
  'taskId', 'operation', 'nonce', 'summary', 'requestedAt', 'expiresAt',
] as const;
const DECISION_FIELDS = [
  'decisionId', 'projectId', 'runId', 'taskId', 'contextFingerprint', 'question', 'options', 'allowFreeText',
  'recommendedOptionId', 'nonce', 'summary', 'requestedAt', 'expiresAt',
] as const;
export const MAX_FREE_TEXT = 2000;
const OPTION_ID_RE = /^[A-Za-z0-9._-]{1,64}$/;
const iso = (ms: number) => new Date(ms).toISOString();

export class RequestService {
  constructor(private readonly db: Db, private readonly cfg: IdpConfig, private readonly key: SigningKey) {}

  /** Marks overdue PENDING items EXPIRED (persisted, audited). */
  expireOverdue(): void {
    const now = this.cfg.now();
    transaction(this.db, () => {
      const a = this.db.prepare("SELECT request_id FROM approval_requests WHERE status = 'PENDING' AND expires_at <= ?").all(now) as { request_id: string }[];
      for (const r of a) audit(this.db, now, 'system', 'approval.expired', r.request_id);
      this.db.prepare("UPDATE approval_requests SET status = 'EXPIRED' WHERE status = 'PENDING' AND expires_at <= ?").run(now);
      const d = this.db.prepare("SELECT decision_id FROM decision_requests WHERE status = 'PENDING' AND expires_at <= ?").all(now) as { decision_id: string }[];
      for (const r of d) audit(this.db, now, 'system', 'decision.expired', r.decision_id);
      this.db.prepare("UPDATE decision_requests SET status = 'EXPIRED' WHERE status = 'PENDING' AND expires_at <= ?").run(now);
    });
  }

  private assertUniqueNonce(nonce: string): void {
    const a = this.db.prepare('SELECT 1 FROM approval_requests WHERE nonce = ?').get(nonce);
    const d = this.db.prepare('SELECT 1 FROM decision_requests WHERE nonce = ?').get(nonce);
    if (a || d) throw new HttpError(409, 'DUPLICATE_NONCE', 'nonce already used');
  }

  // ================= approvals =================

  createApproval(body: unknown): { requestId: string; status: 'PENDING'; approvalUrl: string; expiresAt: string } {
    const o = v.asObject(body);
    v.rejectUnknownKeys(o, APPROVAL_FIELDS);
    const now = this.cfg.now();
    const rec = {
      requestId: v.uuid(o, 'requestId'),
      projectId: v.ident(o, 'projectId')!,
      packageId: v.ident(o, 'packageId')!,
      revision: v.positiveInt(o, 'revision'),
      contextFingerprint: v.ident(o, 'contextFingerprint')!,
      specFingerprint: v.ident(o, 'specFingerprint')!,
      directorSessionId: v.ident(o, 'directorSessionId', true),
      taskId: v.ident(o, 'taskId', true),
      operation: v.ident(o, 'operation')!,
      nonce: v.nonce(o),
      summary: v.summary(o, 'summary', false)!,
      requestedAt: v.isoTime(o, 'requestedAt'),
      expiresAt: v.isoTime(o, 'expiresAt'),
    };
    v.validateWindow(rec.requestedAt, rec.expiresAt, now, this.cfg.maxRequestTtlSeconds);
    transaction(this.db, () => {
      if (this.db.prepare('SELECT 1 FROM approval_requests WHERE request_id = ?').get(rec.requestId)) {
        throw new HttpError(409, 'DUPLICATE_REQUEST', 'requestId already exists');
      }
      this.assertUniqueNonce(rec.nonce);
      this.db
        .prepare(
          `INSERT INTO approval_requests (request_id, project_id, package_id, revision, context_fingerprint, spec_fingerprint,
             director_session_id, task_id, operation, nonce, summary, requested_at, expires_at, received_at, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')`,
        )
        .run(rec.requestId, rec.projectId, rec.packageId, rec.revision, rec.contextFingerprint, rec.specFingerprint,
          rec.directorSessionId ?? null, rec.taskId ?? null, rec.operation, rec.nonce, rec.summary, rec.requestedAt, rec.expiresAt, now);
      audit(this.db, now, 'otonommcp', 'approval.created', rec.requestId, { projectId: rec.projectId, operation: rec.operation });
    });
    return { requestId: rec.requestId, status: 'PENDING', approvalUrl: `${this.cfg.origin}/#/approvals/${rec.requestId}`, expiresAt: iso(rec.expiresAt) };
  }

  private approvalRow(id: string): ApprovalRow {
    this.expireOverdue();
    const row = this.db.prepare('SELECT * FROM approval_requests WHERE request_id = ?').get(String(id).toLowerCase()) as ApprovalRow | undefined;
    if (!row) throw new HttpError(404, 'NOT_FOUND', 'approval request not found');
    return row;
  }

  /** Bearer status endpoint for OtonomMCP. Token only when APPROVED. */
  approvalStatus(id: string): { requestId: string; status: ApprovalStatus; token?: string; reason?: string; decidedAt?: string } {
    const row = this.approvalRow(id);
    const out: { requestId: string; status: ApprovalStatus; token?: string; reason?: string; decidedAt?: string } = { requestId: row.request_id, status: row.status };
    const d = this.db.prepare('SELECT * FROM approval_decisions WHERE request_id = ?').get(row.request_id) as
      | { decision: string; reason: string | null; token: string | null; decided_at: number }
      | undefined;
    if (d) {
      out.decidedAt = iso(d.decided_at);
      if (row.status === 'APPROVED' && d.token) out.token = d.token;
      if (row.status === 'REJECTED' && d.reason) out.reason = d.reason;
    }
    if (row.status === 'EXPIRED') out.reason = 'expired before a decision was made';
    return out;
  }

  approvalView(id: string) {
    const r = this.approvalRow(id);
    const d = this.db.prepare('SELECT decision, reason, decided_at, user_id FROM approval_decisions WHERE request_id = ?').get(r.request_id) as
      | { decision: string; reason: string | null; decided_at: number; user_id: string }
      | undefined;
    return {
      kind: 'approval' as const,
      requestId: r.request_id,
      status: r.status,
      projectId: r.project_id,
      packageId: r.package_id,
      revision: r.revision,
      contextFingerprint: r.context_fingerprint,
      specFingerprint: r.spec_fingerprint,
      directorSessionId: r.director_session_id ?? undefined,
      taskId: r.task_id ?? undefined,
      operation: r.operation,
      nonce: r.nonce,
      summary: JSON.parse(r.summary),
      requestedAt: iso(r.requested_at),
      expiresAt: iso(r.expires_at),
      receivedAt: iso(r.received_at),
      decision: d ? { decision: d.decision, reason: d.reason ?? undefined, decidedAt: iso(d.decided_at) } : undefined,
    };
  }

  /** Approve: caller MUST have verified a fresh UV assertion bound to this requestId (credentialId). */
  approve(id: string, user: User, credentialId: string): { token: string; jti: string } {
    if (!credentialId) throw new HttpError(401, 'ASSERTION_REQUIRED', 'A fresh passkey assertion is required');
    if (user.role !== 'PRODUCT_OWNER') throw new HttpError(403, 'FORBIDDEN', 'Only PRODUCT_OWNER may approve');
    this.expireOverdue();
    return transaction(this.db, () => {
      const r = this.db.prepare('SELECT * FROM approval_requests WHERE request_id = ?').get(id) as ApprovalRow | undefined;
      if (!r) throw new HttpError(404, 'NOT_FOUND', 'approval request not found');
      const now = this.cfg.now();
      if (r.status === 'EXPIRED' || r.expires_at <= now) throw new HttpError(409, 'EXPIRED', 'request expired');
      if (r.status !== 'PENDING') throw new HttpError(409, 'ALREADY_DECIDED', `request already ${r.status}`);
      const iat = Math.floor(now / 1000);
      const jti = crypto.randomUUID();
      const exp = iat + this.cfg.tokenTtlSeconds;
      const claims: Record<string, unknown> = {
        iss: this.cfg.issuer,
        aud: this.cfg.audience,
        sub: user.id,
        preferred_username: user.username,
        actorRole: 'PRODUCT_OWNER',
        nonce: r.nonce,
        jti,
        iat,
        nbf: iat,
        exp,
        requestId: r.request_id,
        decision: 'APPROVED',
        amr: ['webauthn'],
        uv: true,
        projectId: r.project_id,
        packageId: r.package_id,
        revision: r.revision,
        contextFingerprint: r.context_fingerprint,
        specFingerprint: r.spec_fingerprint,
        operation: r.operation,
      };
      if (r.director_session_id) claims.directorSessionId = r.director_session_id;
      if (r.task_id) claims.taskId = r.task_id;
      const token = signEs256(claims, this.key);
      const upd = this.db.prepare("UPDATE approval_requests SET status = 'APPROVED' WHERE request_id = ? AND status = 'PENDING'").run(r.request_id);
      if (upd.changes !== 1) throw new HttpError(409, 'ALREADY_DECIDED', 'request already decided');
      this.db
        .prepare(
          `INSERT INTO approval_decisions (request_id, decision, user_id, credential_id, token, token_jti, token_expires_at, decided_at)
           VALUES (?, 'APPROVED', ?, ?, ?, ?, ?, ?)`,
        )
        .run(r.request_id, user.id, credentialId, token, jti, exp * 1000, now);
      audit(this.db, now, user.id, 'approval.approved', r.request_id, { credentialId, jti });
      return { token, jti };
    });
  }

  reject(id: string, user: User, reasonRaw: unknown): void {
    if (user.role !== 'PRODUCT_OWNER') throw new HttpError(403, 'FORBIDDEN', 'Only PRODUCT_OWNER may reject');
    const reason = v.text({ reason: reasonRaw }, 'reason', 1000)!;
    this.expireOverdue();
    transaction(this.db, () => {
      const r = this.db.prepare('SELECT status, expires_at FROM approval_requests WHERE request_id = ?').get(id) as
        | { status: ApprovalStatus; expires_at: number }
        | undefined;
      if (!r) throw new HttpError(404, 'NOT_FOUND', 'approval request not found');
      if (r.status !== 'PENDING') throw new HttpError(409, 'ALREADY_DECIDED', `request already ${r.status}`);
      const now = this.cfg.now();
      this.db.prepare("UPDATE approval_requests SET status = 'REJECTED' WHERE request_id = ? AND status = 'PENDING'").run(id);
      this.db
        .prepare(`INSERT INTO approval_decisions (request_id, decision, user_id, reason, decided_at) VALUES (?, 'REJECTED', ?, ?, ?)`)
        .run(id, user.id, reason, now);
      audit(this.db, now, user.id, 'approval.rejected', id, { reason });
    });
  }

  // ================= decisions =================

  createDecision(body: unknown): { decisionId: string; status: 'PENDING'; decisionUrl: string; expiresAt: string } {
    const o = v.asObject(body);
    v.rejectUnknownKeys(o, DECISION_FIELDS);
    const now = this.cfg.now();
    const rawOptions = o.options;
    if (!Array.isArray(rawOptions) || rawOptions.length < 2 || rawOptions.length > 6) throw v.bad('options must be an array of 2-6 items');
    const options: DecisionOption[] = rawOptions.map((raw, i) => {
      const opt = v.asObject(raw, `options[${i}]`);
      v.rejectUnknownKeys(opt, ['id', 'label', 'description'], `options[${i}]`);
      if (typeof opt.id !== 'string' || !OPTION_ID_RE.test(opt.id)) throw v.bad(`options[${i}].id must match [A-Za-z0-9._-]{1,64}`);
      const out: DecisionOption = { id: opt.id, label: v.text(opt, 'label', 200)! };
      const desc = v.text(opt, 'description', 1000, true);
      if (desc) out.description = desc;
      return out;
    });
    if (new Set(options.map((x) => x.id)).size !== options.length) throw v.bad('option ids must be unique');
    const rec = {
      decisionId: v.uuid(o, 'decisionId'),
      projectId: v.ident(o, 'projectId')!,
      runId: v.ident(o, 'runId')!,
      taskId: v.ident(o, 'taskId')!,
      contextFingerprint: v.ident(o, 'contextFingerprint')!,
      question: v.text(o, 'question', 2000)!,
      allowFreeText: v.bool(o, 'allowFreeText'),
      recommendedOptionId: o.recommendedOptionId === undefined || o.recommendedOptionId === null ? undefined : o.recommendedOptionId,
      nonce: v.nonce(o),
      summary: v.summary(o, 'summary', true),
      requestedAt: v.isoTime(o, 'requestedAt'),
      expiresAt: v.isoTime(o, 'expiresAt'),
    };
    if (rec.recommendedOptionId !== undefined && !options.some((x) => x.id === rec.recommendedOptionId)) {
      throw v.bad('recommendedOptionId must be one of the option ids');
    }
    v.validateWindow(rec.requestedAt, rec.expiresAt, now, this.cfg.maxRequestTtlSeconds);
    transaction(this.db, () => {
      if (this.db.prepare('SELECT 1 FROM decision_requests WHERE decision_id = ?').get(rec.decisionId)) {
        throw new HttpError(409, 'DUPLICATE_REQUEST', 'decisionId already exists');
      }
      this.assertUniqueNonce(rec.nonce);
      this.db
        .prepare(
          `INSERT INTO decision_requests (decision_id, project_id, run_id, task_id, context_fingerprint, question, options,
             allow_free_text, recommended_option_id, nonce, summary, requested_at, expires_at, received_at, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')`,
        )
        .run(rec.decisionId, rec.projectId, rec.runId, rec.taskId, rec.contextFingerprint, rec.question, JSON.stringify(options),
          rec.allowFreeText ? 1 : 0, (rec.recommendedOptionId as string | undefined) ?? null, rec.nonce, rec.summary ?? null,
          rec.requestedAt, rec.expiresAt, now);
      audit(this.db, now, 'otonommcp', 'decision.created', rec.decisionId, { projectId: rec.projectId, runId: rec.runId });
    });
    return { decisionId: rec.decisionId, status: 'PENDING', decisionUrl: `${this.cfg.origin}/#/decisions/${rec.decisionId}`, expiresAt: iso(rec.expiresAt) };
  }

  private decisionRow(id: string): DecisionRow {
    this.expireOverdue();
    const row = this.db.prepare('SELECT * FROM decision_requests WHERE decision_id = ?').get(String(id).toLowerCase()) as DecisionRow | undefined;
    if (!row) throw new HttpError(404, 'NOT_FOUND', 'decision request not found');
    return row;
  }

  decisionStatus(id: string): { decisionId: string; status: DecisionStatus; token?: string; answeredAt?: string; reason?: string } {
    const row = this.decisionRow(id);
    const out: { decisionId: string; status: DecisionStatus; token?: string; answeredAt?: string; reason?: string } = { decisionId: row.decision_id, status: row.status };
    if (row.status === 'ANSWERED') {
      const a = this.db.prepare('SELECT token, answered_at FROM decision_answers WHERE decision_id = ?').get(row.decision_id) as { token: string; answered_at: number };
      out.token = a.token;
      out.answeredAt = iso(a.answered_at);
    }
    if (row.status === 'EXPIRED') out.reason = 'expired before an answer was given';
    return out;
  }

  decisionView(id: string) {
    const r = this.decisionRow(id);
    const a = this.db.prepare('SELECT selected_option_id, free_text, answered_at FROM decision_answers WHERE decision_id = ?').get(r.decision_id) as
      | { selected_option_id: string | null; free_text: string | null; answered_at: number }
      | undefined;
    return {
      kind: 'decision' as const,
      decisionId: r.decision_id,
      status: r.status,
      projectId: r.project_id,
      runId: r.run_id,
      taskId: r.task_id,
      contextFingerprint: r.context_fingerprint,
      question: r.question,
      options: JSON.parse(r.options) as DecisionOption[],
      allowFreeText: r.allow_free_text === 1,
      maxFreeTextLength: MAX_FREE_TEXT,
      recommendedOptionId: r.recommended_option_id ?? undefined,
      nonce: r.nonce,
      summary: r.summary ? JSON.parse(r.summary) : undefined,
      requestedAt: iso(r.requested_at),
      expiresAt: iso(r.expires_at),
      answer: a ? { selectedOptionId: a.selected_option_id ?? undefined, freeText: a.free_text ?? undefined, answeredAt: iso(a.answered_at) } : undefined,
    };
  }

  /** Validates an answer payload before any WebAuthn step is consumed. */
  validateAnswer(id: string, input: unknown): { selectedOptionId?: string; freeText?: string } {
    const r = this.decisionRow(id);
    const o = v.asObject(input ?? {}, 'answer');
    const sel = o.selectedOptionId === undefined || o.selectedOptionId === null || o.selectedOptionId === '' ? undefined : o.selectedOptionId;
    const options = JSON.parse(r.options) as DecisionOption[];
    if (sel !== undefined && (typeof sel !== 'string' || !options.some((x) => x.id === sel))) throw v.bad('selectedOptionId must be one of the options');
    let freeText: string | undefined;
    if (o.freeText !== undefined && o.freeText !== null && o.freeText !== '') {
      if (r.allow_free_text !== 1) throw v.bad('free text is not allowed for this decision');
      freeText = v.text(o, 'freeText', MAX_FREE_TEXT)!;
    }
    if (sel === undefined && freeText === undefined) throw v.bad('choose an option or enter free text');
    return { selectedOptionId: sel as string | undefined, freeText };
  }

  answer(id: string, user: User, credentialId: string, input: unknown): { token: string; jti: string } {
    if (!credentialId) throw new HttpError(401, 'ASSERTION_REQUIRED', 'A fresh passkey assertion is required');
    if (user.role !== 'PRODUCT_OWNER') throw new HttpError(403, 'FORBIDDEN', 'Only PRODUCT_OWNER may answer');
    const ans = this.validateAnswer(id, input);
    return transaction(this.db, () => {
      const r = this.db.prepare('SELECT * FROM decision_requests WHERE decision_id = ?').get(id) as DecisionRow | undefined;
      if (!r) throw new HttpError(404, 'NOT_FOUND', 'decision request not found');
      const now = this.cfg.now();
      if (r.status === 'EXPIRED' || r.expires_at <= now) throw new HttpError(409, 'EXPIRED', 'decision expired');
      if (r.status !== 'PENDING') throw new HttpError(409, 'ALREADY_ANSWERED', 'decision already answered');
      const iat = Math.floor(now / 1000);
      const jti = crypto.randomUUID();
      const exp = iat + this.cfg.tokenTtlSeconds;
      const claims: Record<string, unknown> = {
        iss: this.cfg.issuer,
        aud: this.cfg.audience,
        sub: user.id,
        preferred_username: user.username,
        actorRole: 'PRODUCT_OWNER',
        nonce: r.nonce,
        jti,
        iat,
        nbf: iat,
        exp,
        decisionId: r.decision_id,
        projectId: r.project_id,
        runId: r.run_id,
        taskId: r.task_id,
        contextFingerprint: r.context_fingerprint,
        amr: ['webauthn'],
        uv: true,
      };
      if (ans.selectedOptionId !== undefined) claims.selectedOptionId = ans.selectedOptionId;
      if (ans.freeText !== undefined) claims.freeText = ans.freeText;
      const token = signEs256(claims, this.key);
      const upd = this.db.prepare("UPDATE decision_requests SET status = 'ANSWERED' WHERE decision_id = ? AND status = 'PENDING'").run(id);
      if (upd.changes !== 1) throw new HttpError(409, 'ALREADY_ANSWERED', 'decision already answered');
      this.db
        .prepare(
          `INSERT INTO decision_answers (decision_id, user_id, credential_id, selected_option_id, free_text, token, token_jti, token_expires_at, answered_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(id, user.id, credentialId, ans.selectedOptionId ?? null, ans.freeText ?? null, token, jti, exp * 1000, now);
      audit(this.db, now, user.id, 'decision.answered', id, { credentialId, jti, selectedOptionId: ans.selectedOptionId });
      return { token, jti };
    });
  }

  // ================= listing =================

  listPending() {
    this.expireOverdue();
    const approvals = this.db
      .prepare("SELECT request_id, project_id, operation, expires_at, requested_at FROM approval_requests WHERE status = 'PENDING' ORDER BY requested_at")
      .all() as { request_id: string; project_id: string; operation: string; expires_at: number; requested_at: number }[];
    const decisions = this.db
      .prepare("SELECT decision_id, project_id, question, expires_at, requested_at FROM decision_requests WHERE status = 'PENDING' ORDER BY requested_at")
      .all() as { decision_id: string; project_id: string; question: string; expires_at: number; requested_at: number }[];
    return {
      approvals: approvals.map((r) => ({ requestId: r.request_id, projectId: r.project_id, operation: r.operation, requestedAt: iso(r.requested_at), expiresAt: iso(r.expires_at) })),
      decisions: decisions.map((r) => ({ decisionId: r.decision_id, projectId: r.project_id, question: r.question, requestedAt: iso(r.requested_at), expiresAt: iso(r.expires_at) })),
    };
  }

  pendingCounts(): { approvals: number; decisions: number } {
    const p = this.listPending();
    return { approvals: p.approvals.length, decisions: p.decisions.length };
  }
}
