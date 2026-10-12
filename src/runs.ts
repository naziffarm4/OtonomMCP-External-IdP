/**
 * Run monitor (contract: idp-run-monitor-contract.md v1). One-way, informational only:
 * nothing stored here is ever read by the approval/decision code paths.
 */
import type { IdpConfig } from './config';
import { transaction, type Db } from './db';
import * as v from './validation';
import { HttpError } from './validation';

export const RUN_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;
export const MAX_EVENTS_PER_RUN = 2000;
export const MAX_RUNS = 200;
export const RUN_STATUSES = ['PENDING_APPROVAL', 'RUNNING', 'BLOCKED_ON_HUMAN', 'WAITING_DECISION', 'COMPLETED', 'FAILED', 'STOPPED', 'CONFIGURATION_ERROR', 'REJECTED'] as const;
export const FINISHED_STATUSES = ['COMPLETED', 'FAILED', 'STOPPED', 'CONFIGURATION_ERROR', 'REJECTED'];
export const EVENT_TYPES = ['RUN_STARTED', 'APPROVAL_REQUESTED', 'MANDATE_SEALED', 'CYCLE_START', 'DIRECTOR_ACTION', 'AGY_DISPATCH', 'AGY_RESULT', 'VERIFICATION', 'CYCLE_RESULT', 'REPLAN', 'ANALYSIS', 'DECISION_REQUESTED', 'DECISION_ANSWERED', 'TASK_ACCEPTED', 'TASK_BLOCKED', 'COMMIT', 'BUDGET', 'RUN_FINISHED', 'INFO'] as const;
const LEVELS = ['info', 'warn', 'error'];
const ENTRY_POINTS = ['aidm_run_spec', 'aidm_autonomous_start'];
const SNAPSHOT_FIELDS = ['runId', 'seq', 'projectId', 'projectName', 'entryPoint', 'status', 'startedAt', 'updatedAt', 'finishedAt', 'model', 'budget', 'currentTaskId', 'tasks', 'lastDirectorAction', 'pendingApprovalId', 'pendingDecisionIds', 'stopReason'];
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const iso = (ms: number) => new Date(ms).toISOString();

function seqOf(o: v.Obj, k = 'seq'): number {
  const x = o[k];
  if (typeof x !== 'number' || !Number.isSafeInteger(x) || x < 0) throw v.bad(`${k} must be an integer >= 0`);
  return x;
}
function nonNegInt(o: v.Obj, k: string, optional = false): number | undefined {
  const x = o[k];
  if (x === undefined && optional) return undefined;
  if (typeof x !== 'number' || !Number.isSafeInteger(x) || x < 0) throw v.bad(`${k} must be an integer >= 0`);
  return x;
}
function money(o: v.Obj, k: string): number {
  const x = o[k];
  if (typeof x !== 'number' || !Number.isFinite(x) || x < 0 || x > 1e9) throw v.bad(`budget.${k} must be a number >= 0`);
  return x;
}
function oneOf(o: v.Obj, k: string, allowed: readonly string[]): string {
  const x = o[k];
  if (typeof x !== 'string' || !allowed.includes(x)) throw v.bad(`${k} must be one of ${allowed.join(', ')}`);
  return x;
}
/** Optional nullable text: undefined/null -> null. */
function optText(o: v.Obj, k: string, max: number): string | null {
  if (o[k] === undefined || o[k] === null) return null;
  return v.text(o, k, max)!;
}
function optIso(o: v.Obj, k: string): string | null {
  if (o[k] === undefined || o[k] === null) return null;
  return iso(v.isoTime(o, k));
}

export interface RunSnapshot {
  runId: string;
  seq: number;
  projectId: string;
  projectName: string;
  entryPoint: string;
  status: string;
  startedAt: string;
  updatedAt: string;
  finishedAt: string | null;
  model: string | null;
  budget: { limitUsd: number; committedUsd: number; reservedUsd: number };
  currentTaskId: string | null;
  tasks: { taskId: string; title: string; status: string; cycles: number; maxAttempts: number | null; lastSummary: string | null }[];
  lastDirectorAction: { actionType: string; taskId: string | null; rationale: string; at: string } | null;
  pendingApprovalId: string | null;
  pendingDecisionIds: string[];
  stopReason: string | null;
}

export function validateRunId(id: string): string {
  if (!RUN_ID_RE.test(id)) throw v.bad('runId must be 1-128 chars [A-Za-z0-9._:-]');
  return id;
}

export function validateSnapshot(pathRunId: string, body: unknown): RunSnapshot {
  const o = v.asObject(body);
  v.rejectUnknownKeys(o, SNAPSHOT_FIELDS);
  if (o.runId !== pathRunId) throw v.bad('runId must equal the path :runId');
  const b = v.asObject(o.budget, 'budget');
  v.rejectUnknownKeys(b, ['limitUsd', 'committedUsd', 'reservedUsd'], 'budget');
  if (!Array.isArray(o.tasks) || o.tasks.length > 100) throw v.bad('tasks must be an array of at most 100 items');
  const tasks = o.tasks.map((raw, i) => {
    const t = v.asObject(raw, `tasks[${i}]`);
    v.rejectUnknownKeys(t, ['taskId', 'title', 'status', 'cycles', 'maxAttempts', 'lastSummary'], `tasks[${i}]`);
    return {
      taskId: v.text(t, 'taskId', 128)!,
      title: v.text(t, 'title', 200)!,
      status: v.text(t, 'status', 40)!,
      cycles: nonNegInt(t, 'cycles')!,
      maxAttempts: nonNegInt(t, 'maxAttempts', true) ?? null,
      lastSummary: optText(t, 'lastSummary', 500),
    };
  });
  let lastDirectorAction: RunSnapshot['lastDirectorAction'] = null;
  if (o.lastDirectorAction !== undefined && o.lastDirectorAction !== null) {
    const a = v.asObject(o.lastDirectorAction, 'lastDirectorAction');
    v.rejectUnknownKeys(a, ['actionType', 'taskId', 'rationale', 'at'], 'lastDirectorAction');
    lastDirectorAction = { actionType: v.text(a, 'actionType', 60)!, taskId: optText(a, 'taskId', 128), rationale: v.text(a, 'rationale', 1000, false, 0)!, at: iso(v.isoTime(a, 'at')) };
  }
  let pendingApprovalId: string | null = null;
  if (o.pendingApprovalId !== undefined && o.pendingApprovalId !== null) pendingApprovalId = v.uuid(o, 'pendingApprovalId');
  if (!Array.isArray(o.pendingDecisionIds) || o.pendingDecisionIds.length > 20) throw v.bad('pendingDecisionIds must be an array of at most 20 uuids');
  const pendingDecisionIds = o.pendingDecisionIds.map((x) => {
    if (typeof x !== 'string' || !UUID_RE.test(x)) throw v.bad('pendingDecisionIds must contain uuids');
    return x.toLowerCase();
  });
  return {
    runId: pathRunId,
    seq: seqOf(o),
    projectId: v.text(o, 'projectId', 128)!,
    projectName: v.text(o, 'projectName', 200)!,
    entryPoint: oneOf(o, 'entryPoint', ENTRY_POINTS),
    status: oneOf(o, 'status', RUN_STATUSES),
    startedAt: iso(v.isoTime(o, 'startedAt')),
    updatedAt: iso(v.isoTime(o, 'updatedAt')),
    finishedAt: optIso(o, 'finishedAt'),
    model: optText(o, 'model', 100),
    budget: { limitUsd: money(b, 'limitUsd'), committedUsd: money(b, 'committedUsd'), reservedUsd: money(b, 'reservedUsd') },
    currentTaskId: optText(o, 'currentTaskId', 128),
    tasks,
    lastDirectorAction,
    pendingApprovalId,
    pendingDecisionIds,
    stopReason: optText(o, 'stopReason', 1000),
  };
}

interface EventIn { seq: number; at: number; type: string; level: string; taskId: string | null; message: string }

export function validateEvents(body: unknown): EventIn[] {
  const o = v.asObject(body);
  v.rejectUnknownKeys(o, ['events']);
  if (!Array.isArray(o.events) || o.events.length < 1 || o.events.length > 50) throw v.bad('events must be an array of 1-50 items');
  return o.events.map((raw, i) => {
    const e = v.asObject(raw, `events[${i}]`);
    v.rejectUnknownKeys(e, ['seq', 'at', 'type', 'level', 'taskId', 'message'], `events[${i}]`);
    return {
      seq: seqOf(e),
      at: v.isoTime(e, 'at'),
      type: oneOf(e, 'type', EVENT_TYPES),
      level: oneOf(e, 'level', LEVELS),
      taskId: optText(e, 'taskId', 128),
      message: v.text(e, 'message', 500)!,
    };
  });
}

interface RunRow {
  run_id: string;
  seq: number;
  has_snapshot: number;
  project_id: string | null;
  project_name: string | null;
  status: string;
  snapshot: string | null;
  updated_at: number;
  received_at: number;
}

export class RunMonitorService {
  constructor(private readonly db: Db, private readonly cfg: IdpConfig) {}

  putSnapshot(pathRunId: string, body: unknown): { runId: string; stored?: true; ignored?: true } {
    const runId = validateRunId(pathRunId);
    const snap = validateSnapshot(runId, body);
    const now = this.cfg.now();
    return transaction(this.db, () => {
      const row = this.db.prepare('SELECT seq, has_snapshot FROM runs WHERE run_id = ?').get(runId) as { seq: number; has_snapshot: number } | undefined;
      if (row && row.has_snapshot === 1 && snap.seq <= row.seq) return { runId, ignored: true as const };
      this.db
        .prepare(
          `INSERT INTO runs (run_id, seq, has_snapshot, project_id, project_name, status, snapshot, updated_at, received_at)
           VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(run_id) DO UPDATE SET seq = excluded.seq, has_snapshot = 1, project_id = excluded.project_id,
             project_name = excluded.project_name, status = excluded.status, snapshot = excluded.snapshot,
             updated_at = excluded.updated_at, received_at = excluded.received_at`,
        )
        .run(runId, snap.seq, snap.projectId, snap.projectName, snap.status, JSON.stringify(snap), Date.parse(snap.updatedAt), now);
      this.enforceRunLimit(runId);
      return { runId, stored: true as const };
    });
  }

  appendEvents(pathRunId: string, body: unknown): { runId: string; accepted: number; duplicates: number } {
    const runId = validateRunId(pathRunId);
    const events = validateEvents(body);
    const now = this.cfg.now();
    return transaction(this.db, () => {
      const exists = this.db.prepare('SELECT 1 FROM runs WHERE run_id = ?').get(runId);
      if (!exists) {
        this.db
          .prepare(`INSERT INTO runs (run_id, seq, has_snapshot, status, updated_at, received_at) VALUES (?, -1, 0, 'RUNNING', ?, ?)`)
          .run(runId, now, now);
      } else {
        this.db.prepare('UPDATE runs SET received_at = ? WHERE run_id = ?').run(now, runId);
      }
      const ins = this.db.prepare(
        `INSERT INTO run_events (run_id, seq, at, type, level, task_id, message, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(run_id, seq) DO NOTHING`,
      );
      let accepted = 0;
      for (const e of events) accepted += Number(ins.run(runId, e.seq, e.at, e.type, e.level, e.taskId, e.message, now).changes);
      // Retention: keep the newest MAX_EVENTS_PER_RUN events (by seq).
      this.db
        .prepare(
          `DELETE FROM run_events WHERE run_id = ? AND seq NOT IN
             (SELECT seq FROM run_events WHERE run_id = ? ORDER BY seq DESC LIMIT ?)`,
        )
        .run(runId, runId, MAX_EVENTS_PER_RUN);
      if (!exists) this.enforceRunLimit(runId);
      return { runId, accepted, duplicates: events.length - accepted };
    });
  }

  /** At most MAX_RUNS runs: drop the oldest finished runs (never the one just written, never active runs). */
  private enforceRunLimit(keep: string): void {
    const n = (this.db.prepare('SELECT COUNT(*) n FROM runs').get() as { n: number }).n;
    if (n <= MAX_RUNS) return;
    const ph = FINISHED_STATUSES.map(() => '?').join(',');
    const victims = this.db
      .prepare(`SELECT run_id FROM runs WHERE status IN (${ph}) AND run_id != ? ORDER BY received_at ASC LIMIT ?`)
      .all(...FINISHED_STATUSES, keep, n - MAX_RUNS) as { run_id: string }[];
    const del = this.db.prepare('DELETE FROM runs WHERE run_id = ?');
    for (const r of victims) del.run(r.run_id); // events cascade
  }

  private summary(r: RunRow) {
    const s = r.snapshot ? (JSON.parse(r.snapshot) as RunSnapshot) : null;
    return {
      runId: r.run_id,
      status: r.status,
      hasSnapshot: r.has_snapshot === 1,
      projectId: r.project_id,
      projectName: r.project_name,
      currentTaskId: s?.currentTaskId ?? null,
      budget: s?.budget ?? null,
      updatedAt: iso(r.updated_at),
      receivedAt: iso(r.received_at),
      active: !FINISHED_STATUSES.includes(r.status),
    };
  }

  list(onlyActive = false) {
    const rows = this.db.prepare('SELECT * FROM runs ORDER BY received_at DESC LIMIT ?').all(MAX_RUNS) as unknown as RunRow[];
    const runs = rows.map((r) => this.summary(r)).filter((r) => !onlyActive || r.active);
    return { serverTime: iso(this.cfg.now()), runs };
  }

  detail(runIdRaw: string, sinceSeqRaw: string | null) {
    const runId = validateRunId(runIdRaw);
    let sinceSeq = -1;
    if (sinceSeqRaw !== null && sinceSeqRaw !== '') {
      if (!/^-?\d{1,15}$/.test(sinceSeqRaw)) throw v.bad('sinceSeq must be an integer');
      sinceSeq = Number(sinceSeqRaw);
    }
    const r = this.db.prepare('SELECT * FROM runs WHERE run_id = ?').get(runId) as RunRow | undefined;
    if (!r) throw new HttpError(404, 'NOT_FOUND', 'run not found');
    const events = (this.db
      .prepare('SELECT seq, at, type, level, task_id, message FROM run_events WHERE run_id = ? AND seq > ? ORDER BY seq DESC LIMIT 500')
      .all(runId, sinceSeq) as { seq: number; at: number; type: string; level: string; task_id: string | null; message: string }[])
      .map((e) => ({ seq: e.seq, at: iso(e.at), type: e.type, level: e.level, taskId: e.task_id, message: e.message }));
    const lastSeq = (this.db.prepare('SELECT MAX(seq) m FROM run_events WHERE run_id = ?').get(runId) as { m: number | null }).m;
    return {
      serverTime: iso(this.cfg.now()),
      run: { ...this.summary(r), snapshot: r.snapshot ? (JSON.parse(r.snapshot) as RunSnapshot) : null },
      events,
      lastSeq: lastSeq ?? -1,
    };
  }
}
