import * as fs from 'node:fs';
import * as path from 'node:path';

const PUB = path.resolve(__dirname, '..', '..', 'public');

class FakeNode {
  nodeType: number;
  tagName?: string;
  children: FakeNode[] = [];
  attrs: Record<string, string> = {};
  listeners: Record<string, (() => void)[]> = {};
  data?: string;
  [k: string]: any;
  constructor(type: number, tag?: string, data?: string) {
    this.nodeType = type;
    this.tagName = tag;
    this.data = data;
  }
  set innerHTML(_v: string) { throw new Error('innerHTML used'); }
  set outerHTML(_v: string) { throw new Error('outerHTML used'); }
  insertAdjacentHTML() { throw new Error('insertAdjacentHTML used'); }
  appendChild(c: FakeNode) { this.children.push(c); return c; }
  removeChild(c: FakeNode) { this.children = this.children.filter((x) => x !== c); return c; }
  get firstChild() { return this.children[0] ?? null; }
  setAttribute(k: string, v: string) { this.attrs[k] = v; }
  addEventListener(ev: string, fn: () => void) { (this.listeners[ev] ||= []).push(fn); }
  get textContent(): string { return this.nodeType === 3 ? this.data! : this.children.map((c) => c.textContent).join(''); }
  all(): FakeNode[] { return [this, ...this.children.flatMap((c) => c.all())]; }
  querySelectorAll(sel: string) {
    const m = /^input\[name="(.+)"\]$/.exec(sel);
    return this.all().filter((n) => n.tagName === 'input' && n.name === m?.[1]);
  }
}
const fakeDoc = {
  createElement: (t: string) => new FakeNode(1, t),
  createTextNode: (s: string) => new FakeNode(3, undefined, s),
};

(globalThis as any).__IDP_TEST__ = true;
// eslint-disable-next-line @typescript-eslint/no-require-imports
const ui = require(path.join(PUB, 'app.js'));

const XSS = '<img src=x onerror=alert(1)><script>alert(2)</script>';

describe('approval UI', () => {
  test('index.html has no inline script/style/handlers and only local scripts', () => {
    const html = fs.readFileSync(path.join(PUB, 'index.html'), 'utf8');
    expect(html).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>/i);
    expect(html).not.toMatch(/\son[a-z]+=/i);
    expect(html).not.toMatch(/<style/i);
    expect(html).not.toMatch(/style=/i);
    for (const m of html.matchAll(/src="([^"]+)"/g)) expect(m[1].startsWith('/')).toBe(true);
    expect(html).not.toMatch(/https?:\/\//);
  });

  test('app.js never uses HTML sinks', () => {
    const js = fs.readFileSync(path.join(PUB, 'app.js'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
    for (const sink of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function', 'setTimeout(\'', 'confirm(']) {
      expect(js).not.toContain(sink);
    }
  });

  test('approval detail renders malicious server strings as text only and shows every binding field', () => {
    const view = {
      requestId: '11111111-1111-4111-8111-111111111111', status: 'PENDING', projectId: XSS, packageId: 'pkg', revision: 7,
      contextFingerprint: 'ctx-fp', specFingerprint: 'spec-fp', directorSessionId: 'dir-1', taskId: 'T-1', operation: 'autonomous.start',
      nonce: 'n'.repeat(20), summary: { title: XSS, budgetUsd: 3 }, requestedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString(),
    };
    const node = ui.renderApprovalDetail(fakeDoc, view, { approve: () => {}, reject: () => {} });
    const text = node.textContent;
    for (const f of ['11111111-1111-4111-8111-111111111111', 'pkg', '7', 'ctx-fp', 'spec-fp', 'dir-1', 'T-1', 'autonomous.start', 'n'.repeat(20)]) {
      expect(text).toContain(f);
    }
    expect(text).toContain(XSS); // literally, as text
    const elements = node.all().filter((n: FakeNode) => n.nodeType === 1).map((n: FakeNode) => n.tagName);
    expect(elements).not.toContain('img');
    expect(elements).not.toContain('script');
  });

  test('rejection reason from server rendered as text', () => {
    const node = ui.renderApprovalDetail(fakeDoc, {
      requestId: 'x', status: 'REJECTED', summary: 's', expiresAt: new Date().toISOString(), requestedAt: new Date().toISOString(),
      decision: { decision: 'REJECTED', reason: XSS, decidedAt: new Date().toISOString() },
    }, null);
    expect(node.textContent).toContain(XSS);
    expect(node.all().some((n: FakeNode) => n.tagName === 'img')).toBe(false);
    expect(node.all().some((n: FakeNode) => n.id === 'approve-btn')).toBe(false);
  });

  test('decision detail: radios, recommended marker, length-limited free text, answer collects selection', () => {
    let got: any[] = [];
    const node = ui.renderDecisionDetail(fakeDoc, {
      decisionId: 'd', status: 'PENDING', question: XSS, projectId: 'p', runId: 'r', taskId: 't', packageId: 'pkg-xyz', revision: 4, operation: 'AUTONOMOUS_DECISION', contextFingerprint: 'c', nonce: 'n',
      options: [{ id: 'a', label: XSS, description: 'desc <b>' }, { id: 'b', label: 'B' }], recommendedOptionId: 'b', allowFreeText: true,
      maxFreeTextLength: 2000, expiresAt: new Date(Date.now() + 60_000).toISOString(), requestedAt: new Date().toISOString(),
    }, { answer: (...a: any[]) => { got = a; } });
    const radios = node.all().filter((n: FakeNode) => n.tagName === 'input' && n.type === 'radio');
    expect(radios.map((r: FakeNode) => r.value)).toEqual(['a', 'b']);
    expect(node.textContent).toContain('Önerilen');
    for (const f of ['pkg-xyz', '4', 'AUTONOMOUS_DECISION']) expect(node.textContent).toContain(f);
    expect(node.textContent).toContain(XSS);
    const ta = node.all().find((n: FakeNode) => n.id === 'free-text');
    expect(ta.maxLength).toBe(2000);
    radios[1].checked = true;
    ta.value = 'hello';
    node.all().find((n: FakeNode) => n.id === 'answer-btn').listeners.click[0]();
    expect(got).toEqual(['b', 'hello']);
  });

  test('pending list links only to in-app hashes and escapes questions', () => {
    const node = ui.renderPending(fakeDoc, {
      approvals: [{ requestId: 'r1', projectId: XSS, operation: 'op', expiresAt: new Date(Date.now() + 1000).toISOString() }],
      decisions: [{ decisionId: 'd1', projectId: 'p', question: XSS, expiresAt: new Date(Date.now() + 1000).toISOString() }],
    });
    const links = node.all().filter((n: FakeNode) => n.tagName === 'a').map((a: FakeNode) => a.attrs.href);
    expect(links).toEqual(['#/approvals/r1', '#/decisions/d1']);
    expect(node.textContent).toContain(XSS);
  });

  test('el() refuses dangerous attributes and external links', () => {
    expect(() => ui.el(fakeDoc, 'a', { href: 'javascript:alert(1)' })).toThrow();
    expect(() => ui.el(fakeDoc, 'div', { innerHTML: 'x' })).toThrow();
    expect(() => ui.el(fakeDoc, 'img', { src: 'x' })).toThrow();
  });

  const serverTime = '2026-10-12T16:00:00.000Z';
  const runSnap = {
    runId: 'run-1', seq: 3, projectId: XSS, projectName: XSS, entryPoint: 'aidm_run_spec', status: 'RUNNING',
    startedAt: '2026-10-12T15:50:00.000Z', updatedAt: '2026-10-12T15:59:50.000Z', finishedAt: null, model: XSS,
    budget: { limitUsd: 4, committedUsd: 1, reservedUsd: 1 }, currentTaskId: 'T2',
    tasks: [{ taskId: 'T1', title: XSS, status: 'ACCEPTED', cycles: 1, maxAttempts: 3, lastSummary: XSS }, { taskId: 'T2', title: 'İki', status: 'IN_PROGRESS', cycles: 2, maxAttempts: null, lastSummary: null }],
    lastDirectorAction: { actionType: 'IMPLEMENT_TASK', taskId: 'T2', rationale: XSS, at: '2026-10-12T15:59:00.000Z' },
    pendingApprovalId: '11111111-1111-4111-8111-111111111111', pendingDecisionIds: ['22222222-2222-4222-8222-222222222222'], stopReason: XSS,
  };
  const detail = (receivedAt: string, status = 'RUNNING') => ({
    serverTime, lastSeq: 2,
    run: { runId: 'run-1', status, projectName: XSS, projectId: XSS, receivedAt, updatedAt: receivedAt, snapshot: { ...runSnap, status } },
    events: [{ seq: 2, at: serverTime, type: 'AGY_RESULT', level: 'error', taskId: XSS, message: XSS }, { seq: 1, at: serverTime, type: 'RUN_STARTED', level: 'info', taskId: null, message: 'başladı' }],
  });

  test('run detail renders every server string as text; budget bar, tasks, timeline, links', () => {
    const node = ui.renderRunDetail(fakeDoc, detail('2026-10-12T15:59:57.000Z'));
    const text = node.textContent;
    expect(text).toContain(XSS);
    expect(node.all().some((n: FakeNode) => n.tagName === 'img' || n.tagName === 'script')).toBe(false);
    expect(text).toContain('Son güncelleme 3 sn önce');
    expect(text).not.toContain('Bağlantı yok');
    const bar = node.all().find((n: FakeNode) => n.tagName === 'progress');
    expect(bar.value).toBe(50);
    expect(text).toContain('$1.00 harcandı + $1.00 ayrıldı / $4.00 (%50)');
    expect(text).toContain('1 / 3');
    const links = node.all().filter((n: FakeNode) => n.tagName === 'a').map((a: FakeNode) => a.attrs.href);
    expect(links).toEqual(['#/approvals/11111111-1111-4111-8111-111111111111', '#/decisions/22222222-2222-4222-8222-222222222222']);
    const evs = node.all().filter((n: FakeNode) => n.tagName === 'li').map((n: FakeNode) => n.textContent);
    expect(evs[0]).toContain('#2');
    expect(evs[1]).toContain('#1');
    expect(text).toContain('Çalışıyor');
  });

  test('stale warning only for RUNNING runs without updates for > 2 min', () => {
    expect(ui.renderRunDetail(fakeDoc, detail('2026-10-12T15:57:00.000Z')).textContent).toContain('Bağlantı yok / duraklamış olabilir');
    expect(ui.renderRunDetail(fakeDoc, detail('2026-10-12T15:57:00.000Z', 'COMPLETED')).textContent).not.toContain('Bağlantı yok');
  });

  test('runs list: text-only, links to in-app run pages, active-only view links to #/runs', () => {
    const data = { serverTime, runs: [{ runId: 'r:1.x', status: 'RUNNING', projectName: XSS, receivedAt: '2026-10-12T15:50:00.000Z', currentTaskId: XSS, budget: { limitUsd: 2, committedUsd: 0.5, reservedUsd: 0 } }] };
    const node = ui.renderRunsList(fakeDoc, data, { activeOnly: true });
    expect(node.textContent).toContain(XSS);
    expect(node.textContent).toContain('bağlantı yok?');
    expect(node.textContent).toContain('$0.50 / $2.00');
    const links = node.all().filter((n: FakeNode) => n.tagName === 'a').map((a: FakeNode) => a.attrs.href);
    expect(links).toEqual(['#/runs/r%3A1.x', '#/runs']);
    expect(ui.renderRunsList(fakeDoc, { serverTime, runs: [] }).textContent).toContain('Henüz çalıştırma yok');
  });
});

