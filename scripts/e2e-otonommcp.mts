/**
 * END-TO-END: the real IdP server process <-> real OtonomMCP (built dist), mocked Director LLM and AGY.
 *
 *   1. starts `node dist/main.js` (real IdP, own data dir, fixed setup code)
 *   2. enrolls a passkey with the software authenticator through the IdP HTTP API
 *   3. OtonomMCP aidm_autonomous_start  -> POST /api/approval-requests on the real IdP
 *   4. approves through the IdP UI API (WebAuthn step-up bound to the requestId)
 *   5. OtonomMCP aidm_autonomous_resume -> polls the IdP, verifies the ES256 token (pinned
 *      AIDM_IDP_PUBLIC_KEY_FILE), seals the mandate, runs the closed loop; the mocked Director asks a
 *      REQUEST_HUMAN_DECISION -> POST /api/decision-requests; a background "human" answers it with a
 *      passkey; OtonomMCP verifies the decision token and finishes the run.
 *
 * Run (needs OtonomMCP built incl. tests/helpers next to dist):
 *   OTONOMMCP_CORE=/path/to/OtonomMCP/packages/core node --experimental-strip-types scripts/e2e-otonommcp.mts
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawn, execSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { pathToFileURL, fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const core = path.resolve(process.env.OTONOMMCP_CORE ?? path.join(root, '..', 'OtonomMCP', 'packages', 'core'));
const imp = (rel: string) => import(pathToFileURL(path.join(core, rel)).href);
const { createAutonomousStartHandler, createAutonomousResumeHandler, createAutonomousStatusHandler } = await imp('dist/mcp/index.js');
const { IdpDecisionResolver } = await imp('dist/autonomous/index.js');
const { NonceStore, createTrustedIdentityProvider } = await imp('dist/authorization/index.js');
const { InMemoryIdentityManager, MockDirectorLlm, MockAgyExecutor } = await imp('tests/helpers/autonomous-test-doubles.ts');
const { SoftAuthenticator } = require(path.join(root, 'dist', 'testing', 'soft-authenticator.js'));
const { BrowserClient } = require(path.join(root, 'dist', 'testing', 'browser-client.js'));

const PORT = Number(process.env.E2E_PORT ?? 7643);
const ORIGIN = `http://localhost:${PORT}`;
const BASE = `http://127.0.0.1:${PORT}`;
const SETUP = 'e2e-setup-code-123';
const results: { name: string; ok: boolean }[] = [];
const check = (name: string, ok: boolean, detail = '') => { results.push({ name, ok }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`); };
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'idp-e2e-data-'));
const proj = fs.mkdtempSync(path.join(os.tmpdir(), 'idp-e2e-proj-'));
const server = spawn(process.execPath, ['--no-warnings=ExperimentalWarning', path.join(root, 'dist', 'main.js')], {
  env: { ...process.env, IDP_DATA_DIR: dataDir, IDP_PORT: String(PORT), IDP_ORIGIN: ORIGIN, IDP_SETUP_CODE: SETUP },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let serverLog = '';
server.stdout.on('data', (d) => { serverLog += d; });
server.stderr.on('data', (d) => { serverLog += d; });

let human: Promise<void> | undefined;
let stopHuman = false;
try {
  for (let i = 0; i < 50; i++) {
    try { if ((await fetch(`${BASE}/healthz`)).ok) break; } catch { /* starting */ }
    await sleep(100);
  }
  check('real IdP process is up (/healthz)', (await fetch(`${BASE}/healthz`)).ok);

  // --- passkey enrollment (software authenticator, real WebAuthn formats) ---
  const auth = new SoftAuthenticator({ origin: ORIGIN, rpId: 'localhost' });
  const b = new BrowserClient(BASE, ORIGIN);
  await b.req('GET', '/api/ui/state');
  const so = await b.req('POST', '/api/setup/options', { setupCode: SETUP, username: 'nazif', displayName: 'Nazif' });
  const sv = await b.req('POST', '/api/setup/verify', { response: auth.register(so.json) });
  check('passkey enrollment via IdP HTTP API', sv.status === 200);

  // --- OtonomMCP environment pointing at the real IdP ---
  const env: Record<string, string> = {
    AIDM_IDP_URL: BASE,
    AIDM_IDP_CLIENT_TOKEN: fs.readFileSync(path.join(dataDir, 'client-token.txt'), 'utf8').trim(),
    AIDM_IDP_PUBLIC_KEY_FILE: path.join(dataDir, 'public-key.pem'),
    AIDM_IDP_ISSUER: 'otonommcp-external-idp',
    AIDM_IDP_AUDIENCE: 'otonommcp',
  };
  for (const c of ['git init -b main', 'git config user.name "AIDM E2E"', 'git config user.email e2e@example.com', 'git config commit.gpgsign false', 'git commit --allow-empty -m init']) {
    execSync(c, { cwd: proj, stdio: 'ignore' });
  }
  fs.writeFileSync(path.join(proj, 'proje.md'), `# Mini Matematik\n\nKüçük bir matematik kütüphanesi.\n\n## Gereksinimler\n\n### Toplama\n\`src/add.js\` içinde add fonksiyonu.\n\n### Çarpma\n\`src/mul.js\` içinde mul fonksiyonu.\n\n## Karar Politikası\nYuvarlama gibi ürün kararlarını bana sor.\n`);
  const llm = new MockDirectorLlm();
  const agy = new MockAgyExecutor(proj);
  let asker: string | undefined;
  let asked = false;
  llm.script = ({ taskId }: { taskId: string }) => {
    if (!asker) asker = taskId;
    if (taskId !== asker || asked) return undefined;
    asked = true;
    return {
      actionType: 'REQUEST_HUMAN_DECISION', rationale: 'Spec leaves rounding open.', question: 'Hangi yuvarlama kuralı?',
      reason: 'Ürün kararı (Karar Politikası).', blocking: true,
      options: [{ id: 'half-up', label: 'Yukarı yuvarla', description: '0.5 -> 1' }, { id: 'bankers', label: 'Banker yuvarlaması', description: '0.5 -> 0' }],
      recommendation: 'half-up',
    };
  };
  const deps = (extra: Record<string, unknown> = {}) => ({
    llmProvider: llm, allowMockProvider: true, identityManager: new InMemoryIdentityManager({ baseDir: proj }),
    registerBudgetTerms: (bm: any) => bm.registerPricingRate({ providerId: 'mock-autonomous', modelId: 'mock-director-1', inputRateNum: 1000n, inputRateDen: 1n, outputRateNum: 2000n, outputRateDen: 1n }),
    executorPort: agy, env, foregroundResume: true, ...extra,
  });
  const parse = (r: any) => JSON.parse(r.content[0].text);

  // --- approval ---
  const start = parse(await createAutonomousStartHandler(deps() as never)({ specPath: 'proje.md', workspaceRoot: proj, budgetUsd: 1 }, {} as never));
  check('OtonomMCP aidm_autonomous_start -> PENDING_EXTERNAL_APPROVAL', start.code === 'PENDING_EXTERNAL_APPROVAL', `${start.code} ${start.message ?? ''}`);
  check('approvalUrl points at the real IdP UI', String(start.approvalUrl).startsWith(`${ORIGIN}/#/approvals/`), start.approvalUrl);
  const requestId = start.requestId as string;
  const pending = await b.req('GET', '/api/ui/pending');
  check('IdP lists the OtonomMCP request as pending', pending.json.approvals.some((a: any) => a.requestId === requestId));
  const view = await b.req('GET', `/api/ui/approvals/${requestId}`);
  check('IdP stored OtonomMCP binding (AUTONOMOUS_SPEC_RUN, rev 1, 64-hex fingerprint)', view.json.operation === 'AUTONOMOUS_SPEC_RUN' && view.json.revision === 1 && /^[0-9a-f]{64}$/.test(view.json.contextFingerprint));
  const early = parse(await createAutonomousResumeHandler(deps() as never)({ workspaceRoot: proj, requestId }, {} as never));
  check('resume before approval stays PENDING (nothing runs)', early.code === 'PENDING_EXTERNAL_APPROVAL' && agy.calls === 0, early.code);

  const ao = await b.req('POST', `/api/ui/approvals/${requestId}/options`, {});
  const ap = await b.req('POST', `/api/ui/approvals/${requestId}/approve`, { assertion: auth.authenticate(ao.json) });
  check('human approves with passkey (WebAuthn step-up)', ap.status === 200, JSON.stringify(ap.json));

  // --- background human answering the Director's decision through the IdP ---
  let answeredDecision: string | undefined;
  human = (async () => {
    while (!stopHuman) {
      const p = await b.req('GET', '/api/ui/pending');
      const d = p.json?.decisions?.[0];
      if (d) {
        const dv = await b.req('GET', `/api/ui/decisions/${d.decisionId}`);
        const o = await b.req('POST', `/api/ui/decisions/${d.decisionId}/options`, {});
        const r = await b.req('POST', `/api/ui/decisions/${d.decisionId}/answer`, { selectedOptionId: 'bankers', freeText: 'Finansal standart', assertion: auth.authenticate(o.json) });
        check('human answers the decision with passkey', r.status === 200, `${dv.json.question} -> bankers; pkg=${dv.json.packageId} op=${dv.json.operation}`);
        answeredDecision = d.decisionId;
        return;
      }
      await sleep(100);
    }
  })();

  const provider = createTrustedIdentityProvider({ env, nonceStore: new NonceStore({ baseDir: proj }) });
  const run = parse(await createAutonomousResumeHandler(deps({ decisionResolver: new IdpDecisionResolver({ env, provider, pollIntervalMs: 100 }) }) as never)({ workspaceRoot: proj, requestId }, {} as never));
  check('OtonomMCP resume verifies IdP token and run COMPLETES', run.code === 'COMPLETED', `${run.code} ${run.report?.stopReason ?? ''} ${run.message ?? ''}`);
  check('mandate authSource is EXTERNAL_IDP', run.report?.authorization?.authSource === 'EXTERNAL_IDP', run.report?.authorization?.authSource);
  check('both tasks ACCEPTED, AGY (mock) called twice', JSON.stringify(run.report?.tasks?.map((t: any) => t.status)) === '["ACCEPTED","ACCEPTED"]' && agy.calls === 2);
  const d = run.report?.decisions?.[0];
  check('Director decision ANSWERED via IdP token (bankers)', d?.state === 'ANSWERED' && d?.answer?.selectedOptionId === 'bankers' && d?.decisionId === answeredDecision, JSON.stringify(d?.answer ?? d));
  check('PO answer was fed back to the Director', llm.requests.some((q: any) => JSON.stringify(q.messages).includes('AUTHORITATIVE PRODUCT_OWNER DECISION')));
  const dst = await (await fetch(`${BASE}/api/decision-requests/${answeredDecision}`, { headers: { Authorization: `Bearer ${env.AIDM_IDP_CLIENT_TOKEN}` } })).json();
  check('IdP reports decision ANSWERED', dst.status === 'ANSWERED');
  const again = parse(await createAutonomousResumeHandler(deps() as never)({ workspaceRoot: proj, requestId }, {} as never));
  check('approval is single use (ALREADY_FINISHED)', /ALREADY_(FINISHED|RUNNING)/.test(again.code), again.code);
  const status = parse(await createAutonomousStatusHandler()({ workspaceRoot: proj, requestId }, {} as never));
  check('aidm_autonomous_status: FINISHED / COMPLETED', status.approvals?.[0]?.state === 'FINISHED' && status.approvals?.[0]?.runStatus === 'COMPLETED');

  // --- rejection path ---
  const start2 = parse(await createAutonomousStartHandler(deps() as never)({ specPath: 'proje.md', workspaceRoot: proj, budgetUsd: 1 }, {} as never));
  await b.req('POST', `/api/ui/approvals/${start2.requestId}/reject`, { reason: 'Bütçe uygun değil' });
  const callsBefore = agy.calls;
  const rej = parse(await createAutonomousResumeHandler(deps() as never)({ workspaceRoot: proj, requestId: start2.requestId }, {} as never));
  check('rejected in IdP -> OtonomMCP REJECTED, nothing runs', rej.code === 'REJECTED' && agy.calls === callsBefore, `${rej.code} ${rej.message ?? ''}`);
} catch (e) {
  check('e2e crashed', false, (e as Error).stack ?? String(e));
} finally {
  stopHuman = true;
  await human?.catch(() => {});
  server.kill('SIGTERM');
  await new Promise((r) => server.once('exit', r));
  check('IdP log never contains the private key or client token', !serverLog.includes('PRIVATE KEY') && !serverLog.includes(fs.existsSync(path.join(dataDir, 'client-token.txt')) ? fs.readFileSync(path.join(dataDir, 'client-token.txt'), 'utf8').trim() : '\u0000'));
  fs.rmSync(dataDir, { recursive: true, force: true });
  fs.rmSync(proj, { recursive: true, force: true });
}
const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} e2e checks passed (OtonomMCP core: ${core})`);
process.exit(failed ? 1 : 0);
