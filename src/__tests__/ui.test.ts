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
      decisionId: 'd', status: 'PENDING', question: XSS, projectId: 'p', runId: 'r', taskId: 't', contextFingerprint: 'c', nonce: 'n',
      options: [{ id: 'a', label: XSS, description: 'desc <b>' }, { id: 'b', label: 'B' }], recommendedOptionId: 'b', allowFreeText: true,
      maxFreeTextLength: 2000, expiresAt: new Date(Date.now() + 60_000).toISOString(), requestedAt: new Date().toISOString(),
    }, { answer: (...a: any[]) => { got = a; } });
    const radios = node.all().filter((n: FakeNode) => n.tagName === 'input' && n.type === 'radio');
    expect(radios.map((r: FakeNode) => r.value)).toEqual(['a', 'b']);
    expect(node.textContent).toContain('Önerilen');
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
});
