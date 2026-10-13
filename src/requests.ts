import * as crypto from 'node:crypto';
import type { IdpConfig } from './config';
import { audit, transaction, type Db } from './db';
import { signEs256 } from './jwt';
import type { SigningKey } from './keys';
import type { User } from './auth';
import * as v from './validation';
import { HttpError } from './validation';
import type { ResumeService } from './resumes';

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
  package_id: string | null;
  revision: number | null;
  operation: string | null;
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
  questions?: string | null;
}

export interface DecisionOption {
  id: string;
  label: string;
  description?: string;
  /** SPEC_CLARIFICATION only: measurable acceptance criteria this option implies (shown to the human). */
  criteria?: string[];
}

/** One question of a SPEC_CLARIFICATION package (contract v1.2). */
export interface ClarificationQuestion {
  id: string;
  /** CLARIFICATION (default): an open point of the spec. IMPROVEMENT: a plan change the Director proposes (accept/reject). */
  kind?: 'CLARIFICATION' | 'IMPROVEMENT';
  question: string;
  reason?: string;
  options: DecisionOption[];
  recommendedOptionId?: string;
  allowFreeText: boolean;
}

export interface ClarificationAnswer {
  questionId: string;
  selectedOptionId?: string;
  freeText?: string;
}

const APPROVAL_FIELDS = [
  'requestId', 'projectId', 'packageId', 'revision', 'contextFingerprint', 'specFingerprint', 'directorSessionId',
  'taskId', 'operation', 'nonce', 'summary', 'requestedAt', 'expiresAt', 'resumeRequestId',
] as const;
const DECISION_FIELDS = [
  'decisionId', 'projectId', 'runId', 'taskId', 'packageId', 'revision', 'operation', 'contextFingerprint', 'question', 'options', 'allowFreeText',
  'recommendedOptionId', 'nonce', 'summary', 'requestedAt', 'expiresAt', 'questions',
] as const;
export const CLARIFICATION_OPERATION = 'SPEC_CLARIFICATION';
export const MAX_CLARIFICATION_QUESTIONS = 12;
export const MAX_FREE_TEXT = 2000;
export const DECISION_OPERATION = 'AUTONOMOUS_DECISION';
const OPTION_ID_RE = /^[A-Za-z0-9._-]{1,64}$/;

function parseOptions(raw: unknown, what: string, min: number, max: number, withCriteria: boolean): DecisionOption[] {
  if (!Array.isArray(raw) || raw.length < min || raw.length > max) throw v.bad(`${what} must be an array of ${min}-${max} items`);
  const options = raw.map((r, i) => {
    const opt = v.asObject(r, `${what}[${i}]`);
    v.rejectUnknownKeys(opt, withCriteria ? ['id', 'label', 'description', 'criteria'] : ['id', 'label', 'description'], `${what}[${i}]`);
    if (typeof opt.id !== 'string' || !OPTION_ID_RE.test(opt.id)) throw v.bad(`${what}[${i}].id must match [A-Za-z0-9._-]{1,64}`);
    const out: DecisionOption = { id: opt.id, label: v.text(opt, 'label', 200)! };
    const desc = v.text(opt, 'description', 1000, true);
    if (desc) out.description = desc;
    if (withCriteria && opt.criteria !== undefined && opt.criteria !== null) {
      if (!Array.isArray(opt.criteria) || opt.criteria.length > 8) throw v.bad(`${what}[${i}].criteria must be an array of at most 8 strings`);
      out.criteria = opt.criteria.map((c, j) => {
        if (typeof c !== 'string' || !c.trim() || c.length > 300) throw v.bad(`${what}[${i}].criteria[${j}] must be a non-empty string <= 300 chars`);
        return c;
      });
    }
    return out;
  });
  if (new Set(options.map((x) => x.id)).size !== options.length) throw v.bad(`${what}: option ids must be unique`);
  return options;
}

function parseQuestions(raw: unknown): ClarificationQuestion[] {
  if (!Array.isArray(raw) || raw.length < 1 || raw.length > MAX_CLARIFICATION_QUESTIONS) {
    throw v.bad(`questions must be an array of 1-${MAX_CLARIFICATION_QUESTIONS} items`);
  }
  const qs = raw.map((r, i) => {
    const q = v.asObject(r, `questions[${i}]`);
    v.rejectUnknownKeys(q, ['id', 'kind', 'question', 'reason', 'options', 'recommendedOptionId', 'allowFreeText'], `questions[${i}]`);
    if (typeof q.id !== 'string' || !OPTION_ID_RE.test(q.id)) throw v.bad(`questions[${i}].id must match [A-Za-z0-9._-]{1,64}`);
    const options = parseOptions(q.options, `questions[${i}].options`, 2, 4, true);
    const out: ClarificationQuestion = { id: q.id, question: v.text(q, 'question', 2000)!, options, allowFreeText: v.bool(q, 'allowFreeText') };
    const reason = v.text(q, 'reason', 1000, true);
    if (reason) out.reason = reason;
    if (q.kind !== undefined && q.kind !== null) {
      if (q.kind !== 'CLARIFICATION' && q.kind !== 'IMPROVEMENT') throw v.bad(`questions[${i}].kind must be CLARIFICATION or IMPROVEMENT`);
      out.kind = q.kind;
    }
    if (q.recommendedOptionId !== undefined && q.recommendedOptionId !== null) {
      if (!options.some((o) => o.id === q.recommendedOptionId)) throw v.bad(`questions[${i}].recommendedOptionId must be one of its option ids`);
      out.recommendedOptionId = q.recommendedOptionId as string;
    }
    return out;
  });
  if (new Set(qs.map((q) => q.id)).size !== qs.length) throw v.bad('question ids must be unique');
  return qs;
}
const iso = (ms: number) => new Date(ms).toISOString();

export class RequestService {
  private resumes?: ResumeService;
  constructor(private readonly db: Db, private readonly cfg: IdpConfig, private readonly key: SigningKey) {}

  /** Enables passkey-signed "Kaldığı yerden devam et" requests to approve pkg-resume requests. */
  attachResumeService(r: ResumeService): void {
    this.resumes = r;
  }

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
    let autoApproved = false;
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
      if (o.resumeRequestId !== undefined && o.resumeRequestId !== null) {
        // Only a resume of the very run the human pressed "Kaldığı yerden devam et" for.
        if (!this.resumes) throw new HttpError(400, 'RESUME_UNSUPPORTED', 'resume requests are not enabled');
        if (!rec.packageId.startsWith('pkg-resume')) throw v.bad('resumeRequestId is only valid for pkg-resume packages');
        const sum = JSON.parse(rec.summary) as { resumeOfRunId?: unknown };
        const rr = this.resumes.consumeForApproval(o.resumeRequestId, rec.projectId, sum.resumeOfRunId, rec.requestId);
        const user = this.db.prepare('SELECT * FROM users WHERE id = ?').get(rr.user_id) as User | undefined;
        if (!user || user.disabled) throw new HttpError(403, 'FORBIDDEN', 'resume requester is no longer active');
        this.approve(rec.requestId, user, rr.credential_id);
        audit(this.db, now, user.id, 'approval.approved_by_resume_request', rec.requestId, { resumeId: rr.resume_id, runId: rr.run_id });
        autoApproved = true;
      }
    });
    if (autoApproved) {
      return { requestId: rec.requestId, status: 'APPROVED' as never, approvalUrl: `${this.cfg.origin}/#/approvals/${rec.requestId}`, expiresAt: iso(rec.expiresAt) };
    }
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
    const isClarification = o.operation === CLARIFICATION_OPERATION;
    let questions: ClarificationQuestion[] | undefined;
    let options: DecisionOption[];
    if (isClarification) {
      questions = parseQuestions(o.questions);
      if (o.options !== undefined && !(Array.isArray(o.options) && o.options.length === 0)) throw v.bad('options must be empty or omitted for SPEC_CLARIFICATION');
      options = [];
    } else {
      if (o.questions !== undefined) throw v.bad(`questions is only allowed with operation '${CLARIFICATION_OPERATION}'`);
      options = parseOptions(o.options, 'options', 2, 6, false);
    }
    const rec = {
      decisionId: v.uuid(o, 'decisionId'),
      projectId: v.ident(o, 'projectId')!,
      runId: v.ident(o, 'runId')!,
      taskId: v.ident(o, 'taskId')!,
      packageId: v.ident(o, 'packageId')!,
      revision: v.positiveInt(o, 'revision'),
      operation: v.ident(o, 'operation')!,
      contextFingerprint: v.ident(o, 'contextFingerprint')!,
      question: v.text(o, 'question', 2000)!,
      allowFreeText: isClarification ? (o.allowFreeText === undefined ? true : v.bool(o, 'allowFreeText')) : v.bool(o, 'allowFreeText'),
      recommendedOptionId: o.recommendedOptionId === undefined || o.recommendedOptionId === null ? undefined : o.recommendedOptionId,
      nonce: v.nonce(o),
      summary: v.summary(o, 'summary', true),
      requestedAt: v.isoTime(o, 'requestedAt'),
      expiresAt: v.isoTime(o, 'expiresAt'),
    };
    if (rec.operation !== DECISION_OPERATION && rec.operation !== CLARIFICATION_OPERATION) {
      throw v.bad(`operation must be '${DECISION_OPERATION}' or '${CLARIFICATION_OPERATION}'`);
    }
    if (isClarification && rec.recommendedOptionId !== undefined) throw v.bad('recommendedOptionId is per question for SPEC_CLARIFICATION');
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
          `INSERT INTO decision_requests (decision_id, project_id, run_id, task_id, package_id, revision, operation, context_fingerprint, question, options,
             allow_free_text, recommended_option_id, nonce, summary, requested_at, expires_at, received_at, status, questions)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?)`,
        )
        .run(rec.decisionId, rec.projectId, rec.runId, rec.taskId, rec.packageId, rec.revision, rec.operation, rec.contextFingerprint, rec.question, JSON.stringify(options),
          rec.allowFreeText ? 1 : 0, (rec.recommendedOptionId as string | undefined) ?? null, rec.nonce, rec.summary ?? null,
          rec.requestedAt, rec.expiresAt, now, questions ? JSON.stringify(questions) : null);
      audit(this.db, now, 'otonommcp', 'decision.created', rec.decisionId, { projectId: rec.projectId, runId: rec.runId, operation: rec.operation, questions: questions?.length });
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
    const a = this.db.prepare('SELECT selected_option_id, free_text, answers, answered_at FROM decision_answers WHERE decision_id = ?').get(r.decision_id) as
      | { selected_option_id: string | null; free_text: string | null; answers: string | null; answered_at: number }
      | undefined;
    return {
      kind: 'decision' as const,
      decisionId: r.decision_id,
      status: r.status,
      projectId: r.project_id,
      runId: r.run_id,
      taskId: r.task_id,
      packageId: r.package_id ?? undefined,
      revision: r.revision ?? undefined,
      operation: r.operation ?? undefined,
      contextFingerprint: r.context_fingerprint,
      question: r.question,
      options: JSON.parse(r.options) as DecisionOption[],
      questions: r.questions ? (JSON.parse(r.questions) as ClarificationQuestion[]) : undefined,
      allowFreeText: r.allow_free_text === 1,
      maxFreeTextLength: MAX_FREE_TEXT,
      recommendedOptionId: r.recommended_option_id ?? undefined,
      nonce: r.nonce,
      summary: r.summary ? JSON.parse(r.summary) : undefined,
      requestedAt: iso(r.requested_at),
      expiresAt: iso(r.expires_at),
      answer: a
        ? {
            selectedOptionId: a.selected_option_id ?? undefined,
            freeText: a.free_text ?? undefined,
            answers: a.answers ? (JSON.parse(a.answers) as ClarificationAnswer[]) : undefined,
            answeredAt: iso(a.answered_at),
          }
        : undefined,
    };
  }

  /** Validates an answer payload before any WebAuthn step is consumed. */
  validateAnswer(id: string, input: unknown): { selectedOptionId?: string; freeText?: string; answers?: ClarificationAnswer[] } {
    const r = this.decisionRow(id);
    const o = v.asObject(input ?? {}, 'answer');
    if (r.questions) {
      // SPEC_CLARIFICATION: every question needs an option or (where allowed) free text.
      const qs = JSON.parse(r.questions) as ClarificationQuestion[];
      if (!Array.isArray(o.answers)) throw v.bad('answers must be an array (one entry per question)');
      const given = new Map<string, Record<string, unknown>>();
      for (const [i, raw] of (o.answers as unknown[]).entries()) {
        const a = v.asObject(raw, `answers[${i}]`);
        v.rejectUnknownKeys(a, ['questionId', 'selectedOptionId', 'freeText'], `answers[${i}]`);
        if (typeof a.questionId !== 'string' || !qs.some((q) => q.id === a.questionId)) throw v.bad(`answers[${i}].questionId is not a question of this request`);
        if (given.has(a.questionId)) throw v.bad(`duplicate answer for ${a.questionId}`);
        given.set(a.questionId, a);
      }
      return {
        answers: qs.map((q) => {
          const a = given.get(q.id) ?? {};
          const sel = a.selectedOptionId === undefined || a.selectedOptionId === null || a.selectedOptionId === '' ? undefined : a.selectedOptionId;
          if (sel !== undefined && (typeof sel !== 'string' || !q.options.some((x) => x.id === sel))) throw v.bad(`${q.id}: selectedOptionId must be one of its options`);
          let freeText: string | undefined;
          if (a.freeText !== undefined && a.freeText !== null && a.freeText !== '') {
            if (!q.allowFreeText) throw v.bad(`${q.id}: free text is not allowed`);
            freeText = v.text(a, 'freeText', MAX_FREE_TEXT)!;
          }
          if (sel === undefined && freeText === undefined) throw v.bad(`${q.id}: choose an option or enter free text`);
          return { questionId: q.id, ...(sel !== undefined ? { selectedOptionId: sel as string } : {}), ...(freeText !== undefined ? { freeText } : {}) };
        }),
      };
    }
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
      if (!r.package_id || !r.revision || !r.operation) {
        // Legacy (pre-v1.1) row: OtonomMCP would refuse a token without the package binding.
        throw new HttpError(409, 'LEGACY_DECISION', 'decision lacks packageId/revision/operation and cannot be answered');
      }
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
        packageId: r.package_id,
        revision: r.revision,
        operation: r.operation,
        contextFingerprint: r.context_fingerprint,
        amr: ['webauthn'],
        uv: true,
      };
      if (ans.selectedOptionId !== undefined) claims.selectedOptionId = ans.selectedOptionId;
      if (ans.freeText !== undefined) claims.freeText = ans.freeText;
      if (ans.answers !== undefined) claims.answers = ans.answers;
      const token = signEs256(claims, this.key);
      const upd = this.db.prepare("UPDATE decision_requests SET status = 'ANSWERED' WHERE decision_id = ? AND status = 'PENDING'").run(id);
      if (upd.changes !== 1) throw new HttpError(409, 'ALREADY_ANSWERED', 'decision already answered');
      this.db
        .prepare(
          `INSERT INTO decision_answers (decision_id, user_id, credential_id, selected_option_id, free_text, token, token_jti, token_expires_at, answered_at, answers)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(id, user.id, credentialId, ans.selectedOptionId ?? null, ans.freeText ?? null, token, jti, exp * 1000, now, ans.answers ? JSON.stringify(ans.answers) : null);
      audit(this.db, now, user.id, 'decision.answered', id, { credentialId, jti, selectedOptionId: ans.selectedOptionId, answers: ans.answers?.length });
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
      .prepare("SELECT decision_id, project_id, question, operation, expires_at, requested_at FROM decision_requests WHERE status = 'PENDING' ORDER BY requested_at")
      .all() as { decision_id: string; project_id: string; question: string; operation: string | null; expires_at: number; requested_at: number }[];
    return {
      approvals: approvals.map((r) => ({ requestId: r.request_id, projectId: r.project_id, operation: r.operation, requestedAt: iso(r.requested_at), expiresAt: iso(r.expires_at) })),
      decisions: decisions.map((r) => ({ decisionId: r.decision_id, projectId: r.project_id, question: r.question, operation: r.operation ?? undefined, requestedAt: iso(r.requested_at), expiresAt: iso(r.expires_at) })),
    };
  }

  pendingCounts(): { approvals: number; decisions: number } {
    const p = this.listPending();
    return { approvals: p.approvals.length, decisions: p.decisions.length };
  }
}
