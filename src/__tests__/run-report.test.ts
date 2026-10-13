import { startHarness, type Harness } from './helpers';
import { MAX_SCREENSHOTS_PER_RUN } from '../runs';

const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';

describe('run completion report + screenshots', () => {
  let h: Harness;
  beforeEach(async () => { h = await startHarness(); });
  afterEach(async () => { await h.close(); });

  test('report + screenshot stored, shown in detail (metadata only), bytes served; auth + validation', async () => {
    expect((await h.bearer('PUT', '/api/runs/r1/report', { summary: 'Özet: 3 görev bitti.' })).status).toBe(200);
    expect((await h.bearer('PUT', '/api/runs/r1/screenshots/index-desktop.png', { caption: 'index.html — masaüstü', dataUrl: PNG })).status).toBe(200);
    expect((await h.bearer('PUT', '/api/runs/r1/report', { summary: 'x' }, '')).status).toBe(401);
    expect((await h.bearer('PUT', '/api/runs/r1/screenshots/a.png', { caption: 'c', dataUrl: 'data:text/html;base64,PHA+' })).status).toBe(400);
    expect((await h.bearer('PUT', '/api/runs/r1/screenshots/..%2Fx', { caption: 'c', dataUrl: PNG })).status).toBe(400);
    const d = h.idp.runs.detail('r1', null) as any;
    expect(d.report.summary).toContain('3 görev');
    expect(d.report.screenshots).toEqual([{ name: 'index-desktop.png', caption: 'index.html — masaüstü' }]);
    const shot = h.idp.runs.screenshot('r1', 'index-desktop.png');
    expect(shot.contentType).toBe('image/png');
    expect(shot.bytes.length).toBeGreaterThan(10);
  });

  test('at most MAX_SCREENSHOTS_PER_RUN per run', async () => {
    for (let i = 0; i < MAX_SCREENSHOTS_PER_RUN; i++) expect((await h.bearer('PUT', `/api/runs/r2/screenshots/s${i}.png`, { caption: 'c', dataUrl: PNG })).status).toBe(200);
    expect((await h.bearer('PUT', '/api/runs/r2/screenshots/extra.png', { caption: 'c', dataUrl: PNG })).status).toBe(409);
  });
});
