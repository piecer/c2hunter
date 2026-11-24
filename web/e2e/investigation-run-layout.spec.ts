import { withLegacyAuthentication } from './auth-fixture';
import { expect, test } from '@playwright/test';
import { fixture } from '../tests/investigationFixtures';
import type { InvestigationRun } from '../src/investigationTypes';

// Real producer fixture through the application, with mocked read-only transport.
for (const width of [1280, 390]) {
  test(`saved IP run retains containment outside the editable form at ${width}px`, async ({ page }, testInfo) => {
    const run = fixture('run_completed') as InvestigationRun;
    const writes: string[] = [];
    await page.setViewportSize({ width, height: 900 });
    await page.addInitScript(() => localStorage.setItem('c2hunter-token', 'fixture-only'));
    await page.route('**/api/v1/**', withLegacyAuthentication(async route => {
      const request = route.request();
      const url = new URL(request.url());
      const path = url.pathname;
      if (request.method() !== 'GET') writes.push(path);
      let body: unknown;
      if (path === `/api/v1/analysis-jobs/${run.job_id}`) body = { id: run.job_id, name: 'Saved investigation', status: 'COMPLETED', analysis: { module: 'c2' } };
      else if (path.endsWith('/candidates')) body = { items: [], total: 0, page: Number(url.searchParams.get('page') ?? '1'), page_size: Number(url.searchParams.get('page_size')) };
      else if (path === '/api/v1/ai-investigations/capabilities') body = fixture('capabilities');
      else if (path.endsWith('/ai-investigations')) body = { items: [run], next_cursor: null };
      else if (path.endsWith('/' + run.id)) body = run;
      else if (path.includes('/evidence/')) body = fixture('evidence_protocol');
      else if (path.endsWith('/steps')) body = { items: [fixture('step_tool')], next_cursor: null };
      else if (path === '/api/v1/ai-capabilities') body = { available: false };
      else body = { items: [] };
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify(body) });
    }));
    await page.goto(`/analyses/${run.job_id}`);
    await page.getByRole('button', { name: 'AI 조사', exact: true }).click();
    await page.getByRole('button', { name: 'IP 조사 열기', exact: true }).click();
    await page.getByRole('button', { name: `${run.target_ip} · ${run.status} ${run.id}`, exact: true }).click();
    const selected = page.getByRole('region', { name: '선택 조사', exact: true });
    await expect(selected).toBeVisible();
    const evidence = fixture('evidence_protocol') as { evidence_id: string };
    await selected.getByRole('button', { name: '발급된 근거', exact: true }).click();
    await selected.getByRole('button', { name: `근거 보기 ${evidence.evidence_id}`, exact: true }).click();
    await expect(selected.getByText('updates.example.test', { exact: true })).toBeVisible();
    const geometry = await page.locator('#ip-investigation-entry').evaluate(element => ({
      client: element.clientWidth, scroll: element.scrollWidth, document: document.documentElement.scrollWidth,
      viewport: innerWidth, nodes: element.querySelectorAll('*').length,
      overflowingControls: [...element.querySelectorAll('button,input,textarea,select')].filter(control => {
        const box = control.getBoundingClientRect();
        return box.width > 0 && (box.right > innerWidth + 1 || box.left < -1);
      }).map(control => control.textContent),
    }));
    await testInfo.attach('saved-run-geometry', { body: JSON.stringify(geometry), contentType: 'application/json' });
    await page.screenshot({ path: testInfo.outputPath('saved-run.png'), fullPage: true });
    expect(geometry.scroll).toBeLessThanOrEqual(geometry.client + 1);
    expect(geometry.document).toBeLessThanOrEqual(geometry.viewport + 1);
    expect(geometry.overflowingControls).toEqual([]);
    expect(geometry.nodes).toBeLessThan(900);
    expect(writes).toEqual([]);
  });
}
