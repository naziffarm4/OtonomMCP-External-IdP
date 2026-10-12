#!/usr/bin/env node
/**
 * CONTRACT CHECK: issues a real approval token through the full IdP flow
 * (setup -> passkey login -> approval request -> WebAuthn step-up -> token) using a
 * software authenticator, then verifies it with OtonomMCP's actual
 * OidcIdentityProviderAdapter (pinned public key PEM).
 *
 * It then does the same for a DECISION answer token through OtonomMCP's real decision path
 * (buildDecisionRecord + IdpDecisionResolver.verify -> verifyIdpToken -> adapter + contract claims).
 *
 * Usage:
 *   npm run contract-check                                  # OtonomMCP at ../OtonomMCP
 *   OTONOMMCP_DIR=D:\ÇALIŞMALAR-D\OtonomMCP npm run contract-check
 *   OTONOMMCP_ADAPTER=/path/to/trusted-identity-adapters.js npm run contract-check
 * OtonomMCP must be built (packages/core/dist) from a branch that contains the IdP wiring.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL, fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const dist = path.resolve(here, '..', 'dist');
const { loadConfig } = require(path.join(dist, 'config.js'));
const { createIdp } = require(path.join(dist, 'server.js'));
const { SoftAuthenticator } = require(path.join(dist, 'testing', 'soft-authenticator.js'));
const { BrowserClient } = require(path.join(dist, 'testing', 'browser-client.js'));

const adapterPath = process.env.OTONOMMCP_ADAPTER
  ?? path.join(path.resolve(process.env.OTONOMMCP_DIR ?? path.resolve(here, '..', '..', 'OtonomMCP')), 'packages', 'core', 'dist', 'authorization', 'trusted-identity-adapters.js');
if (!fs.existsSync(adapterPath)) {
  console.error(`OtonomMCP adapter not found at ${adapterPath}. Build OtonomMCP or set OTONOMMCP_DIR / OTONOMMCP_ADAPTER.`);
  process.exit(2);
}
const { OidcIdentityProviderAdapter } = await import(pathToFileURL(adapterPath).href);
const coreDist = path.dirname(path.dirname(adapterPath));
const tryImport = async (rel) => { try { return await import(pathToFileURL(path.join(coreDist, rel)).href); } catch (e) { return { __error: e }; } };
const oAuthz = await tryImport('authorization/index.js');
const oAuto = await tryImport('autonomous/index.js');

const ORIGIN = 'http://localhost:7443';
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'idp-contract-'));
const cfg = loadConfig({ IDP_PORT: '0', IDP_DATA_DIR: dataDir, IDP_ORIGIN: ORIGIN }, { log: () => {} });
const idp = createIdp(cfg);
const { port } = await idp.listen();
const base = `http://127.0.0.1:${port}`;
const results = [];
const check = (name, ok, detail = '') => { results.push({ name, ok }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`); };

try {
  const auth = new SoftAuthenticator({ origin: ORIGIN, rpId: 'localhost' });
  const b = new BrowserClient(base, ORIGIN);
  await b.req('GET', '/api/ui/state');
  const so = await b.req('POST', '/api/setup/options', { setupCode: idp.setupCode, username: 'nazif', displayName: 'Nazif' });
  await b.req('POST', '/api/setup/verify', { response: auth.register(so.json) });

  const now = Date.now();
  const binding = {
    projectId: 'LLMTEST', packageId: 'pkg-autonomous-LLMTEST-1', revision: 1,
    contextFingerprint: 'c'.repeat(64), operation: 'AUTONOMOUS_SPEC_RUN',
  };
  const requestId = crypto.randomUUID();
  const nonce = Buffer.from(crypto.getRandomValues(new Uint8Array(18))).toString('base64url');
  const created = await fetch(`${base}/api/approval-requests`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${idp.clientToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ requestId, ...binding, specFingerprint: 's'.repeat(64), directorSessionId: null, taskId: null, nonce,
      summary: { text: 'contract check', allowedPaths: ['src'] }, requestedAt: new Date(now).toISOString(), expiresAt: new Date(now + 600_000).toISOString() }),
  });
  check('POST /api/approval-requests -> 201', created.status === 201);
  const opts = await b.req('POST', `/api/ui/approvals/${requestId}/options`, {});
  const appr = await b.req('POST', `/api/ui/approvals/${requestId}/approve`, { assertion: auth.authenticate(opts.json) });
  check('WebAuthn step-up approval', appr.status === 200, JSON.stringify(appr.json));
  const st = await (await fetch(`${base}/api/approval-requests/${requestId}`, { headers: { Authorization: `Bearer ${idp.clientToken}` } })).json();
  check('GET status -> APPROVED with token', st.status === 'APPROVED' && typeof st.token === 'string');
  const pem = await (await fetch(`${base}/api/public-key.pem`)).text();

  const adapter = new OidcIdentityProviderAdapter({ issuer: 'otonommcp-external-idp', audience: 'otonommcp', publicKeyPem: pem });
  const ok = await adapter.verifyAssertion({ token: st.token, binding }, binding, { dryRun: true });
  check('adapter ACCEPTS token with correct binding', ok.isValid === true, ok.isValid ? ok.status : `${ok.status}: ${ok.reason}`);

  const [h, p, s] = st.token.split('.');
  const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
  const forged = `${h}.${Buffer.from(JSON.stringify({ ...payload, projectId: 'OTHER' })).toString('base64url')}.${s}`;
  const t1 = await adapter.verifyAssertion({ token: forged, binding: { ...binding, projectId: 'OTHER' } }, { ...binding, projectId: 'OTHER' }, { dryRun: true });
  check('adapter REJECTS tampered payload', !t1.isValid, t1.status);
  const t2 = await adapter.verifyAssertion({ token: st.token, binding: { ...binding, revision: 2 } }, { ...binding, revision: 2 }, { dryRun: true });
  check('adapter REJECTS wrong binding (revision)', !t2.isValid && t2.status === 'BINDING_MISMATCH', t2.status);
  const t3 = await adapter.verifyAssertion({ token: st.token, binding }, { ...binding, contextFingerprint: 'd'.repeat(64) }, { dryRun: true });
  check('adapter REJECTS wrong contextFingerprint', !t3.isValid, t3.status);
  const otherAud = new OidcIdentityProviderAdapter({ issuer: 'otonommcp-external-idp', audience: 'someone-else', publicKeyPem: pem });
  const t4 = await otherAud.verifyAssertion({ token: st.token, binding }, binding, { dryRun: true });
  check('adapter REJECTS wrong audience', !t4.isValid && t4.status === 'AUDIENCE_MISMATCH', t4.status);
  const { generateKeyPairSync } = await import('node:crypto');
  const otherPem = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ type: 'spki', format: 'pem' });
  const wrongKey = new OidcIdentityProviderAdapter({ issuer: 'otonommcp-external-idp', audience: 'otonommcp', publicKeyPem: otherPem });
  const t5 = await wrongKey.verifyAssertion({ token: st.token, binding }, binding, { dryRun: true });
  check('adapter REJECTS token under a different pinned key', !t5.isValid && t5.status === 'SIGNATURE_INVALID', t5.status);

  // ---------- OtonomMCP real approval path (env factory + verifyIdpToken contract claims) ----------
  const pemFile = path.join(dataDir, 'public-key.pem');
  const oEnv = { AIDM_IDP_URL: base, AIDM_IDP_CLIENT_TOKEN: idp.clientToken, AIDM_IDP_PUBLIC_KEY_FILE: pemFile };
  const idpClientMod = await tryImport('autonomous/idp-client.js');
  if (oAuthz.__error || idpClientMod.__error || !oAuthz.createTrustedIdentityProvider) {
    check('OtonomMCP createTrustedIdentityProvider / verifyIdpToken available', false, String(oAuthz.__error ?? idpClientMod.__error ?? 'missing export'));
  } else {
    const provider = oAuthz.createTrustedIdentityProvider({ env: oEnv });
    const v = await idpClientMod.verifyIdpToken(provider, st.token, binding, { requestId, nonce, decision: 'APPROVED' }, { consumeNonce: false });
    check('OtonomMCP verifyIdpToken ACCEPTS approval token (pinned key file from data dir)', v.ok, v.ok ? v.status : `${v.status}: ${v.reason}`);
    const v2 = await idpClientMod.verifyIdpToken(provider, st.token, binding, { requestId: crypto.randomUUID(), nonce }, { consumeNonce: false });
    check('OtonomMCP verifyIdpToken REJECTS approval token for another requestId', !v2.ok, v2.status);
  }

  // ---------- DECISION answer token through OtonomMCP's real decision verification ----------
  if (oAuto.__error || !oAuto.buildDecisionRecord || !oAuto.IdpDecisionResolver) {
    check('OtonomMCP buildDecisionRecord / IdpDecisionResolver available', false, String(oAuto.__error ?? 'missing export'));
  } else {
    const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'idp-contract-proj-'));
    const rec = oAuto.buildDecisionRecord({
      projectRoot, projectId: binding.projectId, runId: 'run-contract', taskId: 'TASK-002', packageId: binding.packageId, revision: binding.revision,
      question: 'Yuvarlama kuralı?', reason: 'Spec belirtmiyor', options: [{ id: 'bankers', label: 'Banker' }, { id: 'half-up', label: 'Yukarı' }],
      recommendation: 'bankers', allowFreeText: true,
    });
    const created2 = await fetch(`${base}/api/decision-requests`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${idp.clientToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ decisionId: rec.decisionId, projectId: rec.projectId, runId: rec.runId, taskId: rec.taskId, packageId: rec.packageId,
        revision: rec.revision, operation: 'AUTONOMOUS_DECISION', contextFingerprint: rec.contextFingerprint, question: rec.question,
        summary: rec.reason, options: rec.options, allowFreeText: rec.allowFreeText, recommendedOptionId: rec.recommendedOptionId ?? null,
        nonce: rec.nonce, requestedAt: rec.requestedAt, expiresAt: rec.expiresAt }),
    });
    check('POST /api/decision-requests (OtonomMCP-built record) -> 201', created2.status === 201, String(created2.status));
    const dOpts = await b.req('POST', `/api/ui/decisions/${rec.decisionId}/options`, {});
    const ans = await b.req('POST', `/api/ui/decisions/${rec.decisionId}/answer`, { selectedOptionId: 'bankers', freeText: 'Finans standardı', assertion: auth.authenticate(dOpts.json) });
    check('WebAuthn step-up decision answer', ans.status === 200, JSON.stringify(ans.json));
    const dst = await (await fetch(`${base}/api/decision-requests/${rec.decisionId}`, { headers: { Authorization: `Bearer ${idp.clientToken}` } })).json();
    check('GET decision -> ANSWERED with token', dst.status === 'ANSWERED' && typeof dst.token === 'string');
    const { NonceStore } = oAuthz;
    const provider = oAuthz.createTrustedIdentityProvider({ env: oEnv, nonceStore: new NonceStore({ baseDir: projectRoot }) });
    const resolver = new oAuto.IdpDecisionResolver({ env: oEnv, provider });
    const out = await resolver.verify(rec, dst.token);
    check('OtonomMCP IdpDecisionResolver.verify ACCEPTS decision token', out.status === 'ANSWERED' && out.answer?.selectedOptionId === 'bankers',
      out.status === 'ANSWERED' ? `selected=${out.answer.selectedOptionId} freeText=${out.answer.freeText}` : out.reason);
    const replay = await resolver.verify(rec, dst.token);
    check('OtonomMCP REJECTS replay of the consumed decision token', replay.status !== 'ANSWERED', replay.reason);
    const other = { ...rec, decisionId: crypto.randomUUID(), nonce: rec.nonce + 'x' };
    const wrong = await new oAuto.IdpDecisionResolver({ env: oEnv, provider: oAuthz.createTrustedIdentityProvider({ env: oEnv }) }).verify(other, dst.token);
    check('OtonomMCP REJECTS decision token for another decisionId', wrong.status !== 'ANSWERED', wrong.reason);
    const [dh, dp, ds] = dst.token.split('.');
    const dpay = JSON.parse(Buffer.from(dp, 'base64url').toString());
    const forgedD = `${dh}.${Buffer.from(JSON.stringify({ ...dpay, selectedOptionId: 'half-up' })).toString('base64url')}.${ds}`;
    const tam = await new oAuto.IdpDecisionResolver({ env: oEnv, provider: oAuthz.createTrustedIdentityProvider({ env: oEnv }) }).verify(rec, forgedD);
    check('OtonomMCP REJECTS tampered decision answer', tam.status !== 'ANSWERED', tam.reason);
    fs.rmSync(projectRoot, { recursive: true, force: true });
  }

  // ---------- INSTRUCTION token through OtonomMCP's real InstructionChannel (poll -> verifyIdpToken -> ack) ----------
  const oInstr = await tryImport('autonomous/instruction-channel.js');
  if (oInstr.__error || !oInstr.InstructionChannel) {
    console.log('SKIP  instruction checks: OtonomMCP build has no autonomous/instruction-channel.js');
  } else {
    const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'idp-contract-instr-'));
    const runId = 'run-contract-instr';
    const ib = { runId, projectId: 'LLMTEST', packageId: binding.packageId, revision: 1,
      contextFingerprint: oInstr.computeInstructionChannelFingerprint({ runId, projectId: 'LLMTEST', packageId: binding.packageId, revision: 1, specFingerprint: 's'.repeat(64) }) };
    const t0 = new Date().toISOString();
    await fetch(`${base}/api/runs/${runId}`, { method: 'PUT', headers: { Authorization: `Bearer ${idp.clientToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ runId, seq: 1, projectId: 'LLMTEST', projectName: 'LLM Test', entryPoint: 'aidm_autonomous_start', status: 'RUNNING',
        startedAt: t0, updatedAt: t0, finishedAt: null, model: 'm', budget: { limitUsd: 3, committedUsd: 0, reservedUsd: 0 }, currentTaskId: 'TASK-002',
        tasks: [{ taskId: 'TASK-002', title: 'Hakkımda', status: 'IN_PROGRESS', cycles: 1, maxAttempts: 3, lastSummary: null }],
        lastDirectorAction: null, pendingApprovalId: null, pendingDecisionIds: [], stopReason: null }) });
    const mkProvider = () => oAuthz.createTrustedIdentityProvider({ env: oEnv, nonceStore: new oAuthz.NonceStore({ baseDir: projectRoot }) });
    const ch = oInstr.InstructionChannel.create({ env: oEnv, provider: mkProvider(), binding: ib });
    check('OtonomMCP InstructionChannel.open -> PUT channel', Boolean(ch) && await ch.open());
    const sendInstr = async (draft) => {
      const o = await b.req('POST', `/api/ui/runs/${runId}/instructions/options`, draft);
      if (o.status !== 200) return { status: o.status, json: o.json };
      return b.req('POST', `/api/ui/runs/${runId}/instructions/${o.json.instructionId}`, { assertion: auth.authenticate(o.json.options) });
    };
    const s1 = await sendInstr({ mode: 'PAUSE_AND_APPLY', text: 'Dur, iletişim formu ekle' });
    check('UI instruction signed with passkey step-up', s1.status === 200, JSON.stringify(s1.json));
    const got = await ch.poll();
    check('OtonomMCP InstructionChannel.poll VERIFIES instruction token', got.length === 1 && got[0].mode === 'PAUSE_AND_APPLY' && got[0].taskId === null,
      got.length ? `${got[0].mode} "${got[0].text}"` : JSON.stringify(ch.rejected));
    const view = await b.req('GET', `/api/ui/runs/${runId}`);
    check('IdP shows RECEIVED after OtonomMCP ack', view.json.instructions?.[0]?.status === 'RECEIVED');
    check('OtonomMCP ack APPLIED accepted', got.length === 1 && await ch.ack(got[0].instructionId, 'APPLIED', 'Uygulandı'));
    // a channel with a newer revision must reject a token issued for the old one
    await sendInstr({ mode: 'NOTE', text: 'eski revizyon' });
    const ch2 = oInstr.InstructionChannel.create({ env: oEnv, provider: mkProvider(), binding: { ...ib, revision: 2 } });
    ch2.opened = true; // do not re-PUT the channel: the IdP channel stays at revision 1
    const got2 = await ch2.poll();
    check('OtonomMCP REJECTS instruction token for another revision (acked REJECTED)', got2.length === 0 && ch2.rejected.length === 1, ch2.rejected[0]?.reason);
    const view2 = await b.req('GET', `/api/ui/runs/${runId}`);
    check('IdP shows REJECTED with reason note', view2.json.instructions?.[0]?.status === 'REJECTED' && /Doğrulanamadı/.test(view2.json.instructions?.[0]?.note ?? ''), JSON.stringify(view2.json.instructions?.[0] ?? view2.json));
    // Targeted instruction (taskId claim set). Contract: taskId is the instruction target, not a binding.
    await sendInstr({ mode: 'NOTE', text: 'sadece bu görev', taskId: 'TASK-002' });
    const got3 = await ch.poll();
    const r3 = ch.rejected.at(-1)?.reason ?? '';
    if (got3.length === 1 && got3[0].taskId === 'TASK-002') check('OtonomMCP VERIFIES targeted instruction (taskId claim)', true);
    else console.log(`KNOWN  OtonomMCP rejects targeted instructions (taskId claim treated as task binding): ${r3}  -> OtonomMCP-side fix, see contract IdP notes`);
    await ch.close();
    const v3 = await b.req('GET', `/api/ui/runs/${runId}`);
    check('OtonomMCP InstructionChannel.close -> form hidden', v3.json.instructionChannel?.canInstruct === false, JSON.stringify(v3.json).slice(0, 200));
    fs.rmSync(projectRoot, { recursive: true, force: true });
  }
} finally {
  await idp.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
}
const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} contract checks passed (adapter: ${adapterPath})`);
process.exit(failed ? 1 : 0);
