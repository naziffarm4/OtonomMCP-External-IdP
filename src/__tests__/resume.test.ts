import { verifyEs256 } from '../jwt';
import { approvalBody, decodeJwt, enroll, startHarness, type Harness } from './helpers';
import { snapshot } from './runs.test';

const RUN = 'run-2026-10-13T04-30-34-841Z-6a32b0';
describe('"Kaldığı yerden devam et" resume requests', () => {
  let h: Harness;
  beforeEach(async () => { h = await startHarness(); });
  afterEach(async () => { await h.close(); });

  const put = (status: string) => h.idp.runs.putSnapshot(RUN, snapshot({ runId: RUN, projectId: 'proj-LLMTEST', status, seq: Date.now() % 1e9 }));
  async function press(browser: any, auth: any) {
    const o = await browser.req('POST', `/api/ui/runs/${RUN}/resume/options`, {});
    if (o.status !== 200) return o;
    expect(o.json.options.userVerification).toBe('required');
    return browser.req('POST', `/api/ui/runs/${RUN}/resume/${o.json.resumeId}`, { assertion: auth.authenticate(o.json.options) });
  }
  const resumeApproval = (resumeRequestId: string, over: Record<string, unknown> = {}) =>
    approvalBody(h, { packageId: 'pkg-resume-abc-123', directorSessionId: null, taskId: null, summary: { resumeOfRunId: RUN }, resumeRequestId, ...over });

  test('passkey press -> watcher claims -> pkg-resume approval is approved with that passkey (one prompt)', async () => {
    put('BLOCKED_ON_HUMAN');
    const { browser, auth } = await enroll(h);
    const ui = await browser.req('GET', `/api/ui/runs/${RUN}`);
    expect(ui.json.resume).toMatchObject({ canResume: true, runId: RUN });
    const r = await press(browser, auth);
    expect(r.status).toBe(200);
    expect(r.json.status).toBe('PENDING');
    // second press while one is in flight is refused
    expect((await browser.req('POST', `/api/ui/runs/${RUN}/resume/options`, {})).status).toBe(409);

    const list = await h.bearer('GET', '/api/resume-requests?status=PENDING');
    expect(list.json.items).toEqual([expect.objectContaining({ resumeId: r.json.resumeId, runId: RUN, projectId: 'proj-LLMTEST' })]);
    expect((await h.bearer('POST', `/api/resume-requests/${r.json.resumeId}/claim`, {})).status).toBe(200);
    expect((await h.bearer('POST', `/api/resume-requests/${r.json.resumeId}/claim`, {})).status).toBe(409);

    const body = resumeApproval(r.json.resumeId);
    const created = await h.bearer('POST', '/api/approval-requests', body);
    expect(created.status).toBe(201);
    expect(created.json.status).toBe('APPROVED');
    const st = await h.bearer('GET', `/api/approval-requests/${body.requestId}`);
    expect(st.json.status).toBe('APPROVED');
    const { payload } = decodeJwt(st.json.token);
    expect(payload).toMatchObject({ requestId: body.requestId, packageId: 'pkg-resume-abc-123', amr: ['webauthn'], uv: true, nonce: body.nonce });
    expect(() => verifyEs256(st.json.token, h.idp.key.publicKeyPem, h.idp.key.kid, { issuer: 'otonommcp-external-idp', audience: 'otonommcp', now: h.clock.now })).not.toThrow();

    // single use
    const again = await h.bearer('POST', '/api/approval-requests', resumeApproval(r.json.resumeId));
    expect(again.status).toBe(409);
    expect((await h.bearer('POST', `/api/resume-requests/${r.json.resumeId}/result`, { status: 'STARTED', note: 'WORKER_STARTED' })).status).toBe(200);
    expect((await browser.req('GET', `/api/ui/runs/${RUN}`)).json.resume.pending.status).toBe('APPROVED');
  });

  test('binding: unclaimed, other run, non-resume package and expired requests never approve', async () => {
    put('BLOCKED_ON_HUMAN');
    const { browser, auth } = await enroll(h);
    const r = await press(browser, auth);
    const id = r.json.resumeId;
    expect((await h.bearer('POST', '/api/approval-requests', resumeApproval(id))).status).toBe(409); // not claimed
    await h.bearer('POST', `/api/resume-requests/${id}/claim`, {});
    expect((await h.bearer('POST', '/api/approval-requests', resumeApproval(id, { summary: { resumeOfRunId: 'run-other' } }))).status).toBe(409);
    expect((await h.bearer('POST', '/api/approval-requests', resumeApproval(id, { projectId: 'proj-OTHER' }))).status).toBe(409);
    expect((await h.bearer('POST', '/api/approval-requests', resumeApproval(id, { packageId: 'pkg-autonomous-x' }))).status).toBe(400);
    h.clock.now += 16 * 60_000;
    expect((await h.bearer('POST', '/api/approval-requests', resumeApproval(id))).status).toBe(409);
    expect((await browser.req('GET', `/api/ui/runs/${RUN}`)).json.resume.pending.status).toBe('EXPIRED');
  });

  test('running runs offer no button; machine API needs bearer; UI needs a session', async () => {
    put('RUNNING');
    const { browser, auth } = await enroll(h);
    expect((await browser.req('GET', `/api/ui/runs/${RUN}`)).json.resume.canResume).toBe(false);
    expect((await press(browser, auth)).status).toBe(409);
    expect((await h.bearer('GET', '/api/resume-requests', undefined, 'wrong-token')).status).toBe(401);
  });
});
