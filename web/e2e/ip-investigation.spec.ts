import { expect, test } from '@playwright/test';
import { fixture } from '../tests/investigationFixtures';
import type { InvestigationRequest, InvestigationRun } from '../src/investigationTypes';

// Browser/layout acceptance with source-bound producer bytes and a controlled HTTP
// schedule. NOT real model inference, worker integration, or operating acceptance.
for (const width of [1280, 390]) {
  test(`IP investigation preserves identifiers and automatic terminal results at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    const errors: string[] = [];
    const admissions: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
    await page.addInitScript(() => localStorage.setItem('c2hunter-token', 'ui-fixture-only'));
    const longIP = '2001:0db8:1234:5678:90ab:cdef:1234:5678';
    const completed = fixture('run_completed') as InvestigationRun;
    let captured: InvestigationRequest | undefined;
    let reads = 0;
    await page.route('**/api/v1/**', async route => {
      const request = route.request();
      const url = new URL(request.url());
      const path = url.pathname;
      let body: unknown;
      if (path === '/api/v1/ai-investigations/capabilities') body = fixture('capabilities');
      else if (path.endsWith('/source-preview')) body = fixture('source_preview');
      else if (path.endsWith('/ai-investigations') && request.method() === 'POST') {
        admissions.push(request.postData()!); captured = request.postDataJSON();
        body = { ...(fixture('run_queued') as object), request: captured };
      } else if (path.endsWith('/ai-investigations')) body = { items: [], next_cursor: null };
      else if (path.endsWith('/' + completed.id)) {
        reads += 1;
        body = { ...(reads === 1 ? fixture('run_queued') as object : completed), request: captured };
      } else if (path.includes('/evidence/')) body = fixture('evidence_protocol');
      else if (path.endsWith('/steps')) body = { items: [fixture('step_tool')], next_cursor: null };
      else if (path === '/api/v1/analysis-jobs/job') body = { id: 'job', name: 'Long source label '.repeat(12), status: 'COMPLETED', analysis: { module: 'c2' } };
      else if (path.endsWith('/candidates')) body = { items: Array.from({ length: 7 }, (_, index) => ({ id: `candidate-${index}`, candidate_ip: index === 6 ? longIP : `198.51.100.${index + 1}`, score: 42, severity: 'MEDIUM' })) };
      else if (path.endsWith('/flows')) body = { items: [{ flow_id: 'flow', job_id: 'job', timestamp: '2026-01-01T00:00:00Z', source_ip: '10.0.0.12', destination_ip: longIP, protocol: 'UDP', direction: 'OUTBOUND' }], total: 1, page: 1, page_size: 50 };
      else if (path === '/api/v1/ai-capabilities') body = { available: false };
      else body = { items: [] };
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify(body) });
    });
    await page.goto('/analyses/job');
    const panel = page.getByRole('region', { name: 'IP 조사 / IP investigation', exact: true });
    await page.getByRole('button', { name: `Investigate candidate ${longIP}`, exact: true }).click();
    await expect(panel.getByLabel('대상 IP / Target IP')).toHaveValue(longIP);
    await expect(panel.getByLabel('대상 IP / Target IP')).toBeFocused();
    await page.getByRole('button', { name: 'Investigate source 10.0.0.12', exact: true }).click();
    await expect(panel.getByLabel('대상 IP / Target IP')).toHaveValue('10.0.0.12');
    await page.getByRole('button', { name: `Investigate destination ${longIP}`, exact: true }).click();
    await expect(panel.getByLabel('대상 IP / Target IP')).toHaveValue(longIP);
    await panel.getByText('범위 제한 / Scope filters', { exact: true }).click();
    await panel.getByLabel('엔드포인트 / Endpoint').selectOption('either');
    await panel.getByLabel('대상 IP / Target IP').fill('2001:db8::1');
    await panel.getByLabel('질문 / Question').fill('<img src=x onerror=alert(1)> ' + '분석 질문 '.repeat(200));
    await panel.getByRole('button', { name: '범위 미리보기 / Preview scope', exact: true }).click();
    await panel.getByRole('button', { name: '조사 시작 / Start investigation', exact: true }).click();
    // No refresh, route change, selector action or priming GET before terminal.
    await expect(panel.getByText('관측된 통신은 추가 검토가 필요합니다.', { exact: true })).toBeVisible({ timeout: 10000 });
    expect(admissions).toHaveLength(1);
    expect(JSON.parse(admissions[0]).allow_remote).toBe(false);
    await expect(panel.locator('img')).toHaveCount(0);
    const evidence = fixture('evidence_protocol') as { evidence_id: string };
    await panel.getByRole('button', { name: `근거 보기 / Evidence ${evidence.evidence_id}`, exact: true }).click();
    await expect(panel.getByText('updates.example.test', { exact: true })).toBeVisible();
    const geometry = await panel.evaluate(element => ({
      panelClient: element.clientWidth, panelScroll: element.scrollWidth,
      viewport: innerWidth, document: document.documentElement.scrollWidth,
      nodes: element.querySelectorAll('*').length,
      overflowingControls: [...element.querySelectorAll('button,input,textarea,select')].filter(control => {
        const box = control.getBoundingClientRect();
        return box.width > 0 && (box.right > innerWidth + 1 || box.left < -1);
      }).map(control => control.textContent),
    }));
    expect(geometry.panelScroll).toBeLessThanOrEqual(geometry.panelClient + 1);
    expect(geometry.document).toBeLessThanOrEqual(geometry.viewport + 1);
    expect(geometry.overflowingControls).toEqual([]);
    expect(geometry.nodes).toBeLessThan(900);
    expect(errors).toEqual([]);
    await testInfo.attach('investigation-geometry', { body: JSON.stringify(geometry), contentType: 'application/json' });
    await testInfo.attach('investigation-layout', { body: await panel.screenshot(), contentType: 'image/png' });
  });
}
