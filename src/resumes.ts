/**
 * "Kaldığı yerden devam et": passkey-signed resume requests for stopped runs.
 *
 * Flow: UI (session + CSRF + fresh UV passkey assertion bound to runId) -> PENDING resume request.
 * The OtonomMCP aidm watcher (bearer) lists PENDING requests, claims one (CLAIMED), and starts the
 * run's normal pkg-resume approval request carrying resumeRequestId. RequestService approves that
 * approval request with this request's passkey assertion (one prompt in total) -> APPROVED.
 * Single use, short-lived, audited; never approves anything but a pkg-resume of the same run.
 */
import * as crypto from 'node:crypto';
import type { IdpConfig } from './config';
import type { User } from './auth';
import { audit, transaction, type Db } from './db';
import * as v from './validation';
import { HttpError } from './validation';
import { validateRunId } from './runs';

export const RESUME_TTL_MS = 15 * 60 * 1000;
/** Run statuses that offer the button (stale RUNNING = interrupted). OtonomMCP re-checks resumability. */
export const RESUMABLE_RUN_STATUSES = ['BLOCKED_ON_HUMAN', 'FAILED', 'STOPPED', 'WAITING_DECISION'];
const iso = (ms: number) => new Date(ms).toISOString();

export interface ResumeRow {
  resume_id: string;
  run_id: string;
  project_id: string;
  user_id: string;
  credential_id: string;
  status: 'PENDING' | 'CLAIMED' | 'STARTED' | 'APPROVED' | 'FAILED' | 'EXPIRED';
  approval_request_id: string | null;
  note: string | null;
  created_at: number;
  expires_at: number;
  claimed_at: number | null;
  finished_at: number | null;
}

const view = (r: ResumeRow) => ({
  resumeId: r.resume_id,
  runId: r.run_id,
  projectId: r.project_id,
  status: r.status,
  note: r.note,
  createdAt: iso(r.created_at),
  expiresAt: iso(r.expires_at),
  approvalRequestId: r.approval_request_id,
});

export class ResumeService {
  constructor(private readonly db: Db, private readonly cfg: IdpConfig) {}

  expireOverdue(): void {
    const now = this.cfg.now();
    this.db.prepare("UPDATE resume_requests SET status = 'EXPIRED', finished_at = ? WHERE status IN ('PENDING','CLAIMED','STARTED') AND expires_at <= ?").run(now, now);
  }

  /** Whether the run may be resumed from the UI, and why not. */
  eligibility(runIdRaw: string): { runId: string; projectId: string | null; canResume: boolean; reason: string | null; pending: ReturnType<typeof view> | null } {
    const runId = validateRunId(runIdRaw);
    this.expireOverdue();
    const r = this.db.prepare('SELECT status, project_id, received_at FROM runs WHERE run_id = ?').get(runId) as { status: string; project_id: string | null; received_at: number } | undefined;
    if (!r) throw new HttpError(404, 'NOT_FOUND', 'run not found');
    const last = this.db.prepare('SELECT * FROM resume_requests WHERE run_id = ? ORDER BY created_at DESC LIMIT 1').get(runId) as ResumeRow | undefined;
    const open = last && ['PENDING', 'CLAIMED', 'STARTED'].includes(last.status) ? last : undefined;
    const stale = r.status === 'RUNNING' && this.cfg.now() - r.received_at > this.cfg.runStaleSeconds * 1000;
    let reason: string | null = null;
    if (!r.project_id) reason = 'Çalıştırmanın proje bilgisi yok.';
    else if (!(RESUMABLE_RUN_STATUSES.includes(r.status) || stale)) reason = `Çalıştırma durumu ${r.status}; devam ettirilemez.`;
    else if (open) reason = 'Bu çalıştırma için bir devam isteği zaten işleniyor.';
    return { runId, projectId: r.project_id, canResume: reason === null, reason, pending: last ? view(last) : null };
  }

  /** Caller verified a fresh UV assertion bound to (session, 'resume', resumeId, {runId}). */
  create(resumeId: string, runIdRaw: string, user: User, credentialId: string) {
    if (!credentialId) throw new HttpError(401, 'ASSERTION_REQUIRED', 'A fresh passkey assertion is required');
    if (user.role !== 'PRODUCT_OWNER') throw new HttpError(403, 'FORBIDDEN', 'Only PRODUCT_OWNER may resume runs');
    return transaction(this.db, () => {
      const e = this.eligibility(runIdRaw);
      if (!e.canResume) throw new HttpError(409, 'NOT_RESUMABLE', e.reason ?? 'not resumable');
      const now = this.cfg.now();
      this.db
        .prepare(
          `INSERT INTO resume_requests (resume_id, run_id, project_id, user_id, credential_id, status, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, 'PENDING', ?, ?)`,
        )
        .run(resumeId, e.runId, e.projectId!, user.id, credentialId, now, now + RESUME_TTL_MS);
      audit(this.db, now, user.id, 'resume.requested', resumeId, { runId: e.runId, credentialId });
      return view(this.db.prepare('SELECT * FROM resume_requests WHERE resume_id = ?').get(resumeId) as unknown as ResumeRow);
    });
  }

  // ---------- machine side (bearer) ----------
  listPending(status: string | null) {
    if (status !== null && status !== 'PENDING') throw v.bad('status must be PENDING');
    this.expireOverdue();
    const rows = this.db.prepare("SELECT * FROM resume_requests WHERE status = 'PENDING' ORDER BY created_at ASC LIMIT 20").all() as unknown as ResumeRow[];
    return { items: rows.map(view) };
  }

  claim(idRaw: string) {
    const id = this.uuid(idRaw);
    this.expireOverdue();
    const now = this.cfg.now();
    const upd = this.db.prepare("UPDATE resume_requests SET status = 'CLAIMED', claimed_at = ? WHERE resume_id = ? AND status = 'PENDING'").run(now, id);
    if (upd.changes !== 1) throw new HttpError(409, 'NOT_PENDING', 'resume request is not pending');
    audit(this.db, now, 'otonommcp', 'resume.claimed', id);
    return { ok: true, resumeId: id, status: 'CLAIMED' };
  }

  result(idRaw: string, body: unknown) {
    const id = this.uuid(idRaw);
    const o = v.asObject(body);
    v.rejectUnknownKeys(o, ['status', 'note']);
    if (o.status !== 'STARTED' && o.status !== 'FAILED') throw v.bad('status must be STARTED or FAILED');
    const note = v.text(o, 'note', 500, true) ?? null;
    const now = this.cfg.now();
    const upd = this.db
      .prepare(`UPDATE resume_requests SET status = CASE WHEN status = 'APPROVED' AND ? = 'STARTED' THEN 'APPROVED' ELSE ? END, note = ?, finished_at = ? WHERE resume_id = ? AND status IN ('CLAIMED','APPROVED')`)
      .run(o.status, o.status, note, now, id);
    if (upd.changes !== 1) throw new HttpError(409, 'NOT_CLAIMED', 'resume request is not claimed');
    audit(this.db, now, 'otonommcp', 'resume.result', id, { status: o.status, note });
    return { ok: true };
  }

  /**
   * Used by RequestService.createApproval inside its transaction: a CLAIMED, unexpired resume
   * request for the same project + run is consumed and its user/credential approve the request.
   */
  consumeForApproval(idRaw: unknown, projectId: string, runId: unknown, approvalRequestId: string): ResumeRow {
    const id = this.uuid(idRaw);
    const r = this.db.prepare('SELECT * FROM resume_requests WHERE resume_id = ?').get(id) as ResumeRow | undefined;
    const now = this.cfg.now();
    if (!r) throw new HttpError(404, 'RESUME_NOT_FOUND', 'resume request not found');
    if (r.status !== 'CLAIMED' || r.expires_at <= now) throw new HttpError(409, 'RESUME_NOT_USABLE', `resume request is ${r.expires_at <= now ? 'EXPIRED' : r.status}`);
    if (r.project_id !== projectId || r.run_id !== runId) throw new HttpError(409, 'RESUME_BINDING_MISMATCH', 'resume request belongs to a different run');
    const upd = this.db
      .prepare("UPDATE resume_requests SET status = 'APPROVED', approval_request_id = ? WHERE resume_id = ? AND status = 'CLAIMED'")
      .run(approvalRequestId, id);
    if (upd.changes !== 1) throw new HttpError(409, 'RESUME_NOT_USABLE', 'resume request already used');
    return r;
  }

  private uuid(x: unknown): string {
    if (typeof x !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(x)) throw v.bad('resumeId must be a uuid');
    return x.toLowerCase();
  }
}

export const newResumeId = (): string => crypto.randomUUID();
