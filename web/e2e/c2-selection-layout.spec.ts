import { expect, test, type Locator, type Page } from '@playwright/test';
import { installApiFixture } from './route-fixture';

// Browser layout proof with mocked API responses, not real PCAP/model acceptance.
const ips = ['2001:0db8:1234:5678:90ab:cdef:1234:5678', '203.0.113.10', '2001:0db8:ffff:eeee:dddd:cccc:bbbb:aaaa', '198.51.100.20'];
const origins = ['RULE_AND_BEHAVIOR', 'RULE', 'BEHAVIOR', 'PREFILTER'];
const datasetId = `pcap:${'a'.repeat(64)}`;
const run = {
  id: 'layout-run', analysis_job_id: 'job-1', status: 'COMPLETED', progress_percent: 100,
  candidate_count: 3, created_at: '2026-07-20T10:15:00Z', discovery_mode: 'shadow',
  selection_summary: {
    version: 'behavior-selection-v1', candidate_pool_count: 21, selected_count: 3, omitted_count: 18,
    discovery_candidate_count: 2, discovery_selected_count: 2, rule_free_selected_count: 1,
    reserved_discovery_slots: 2, warnings: [],
  },
};

async function installSelectionFixture(page: Page) {
  await installApiFixture(page);
  await page.route('**/api/v1/**', async route => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace('/api/v1', '');
    let body: unknown;
    if (path === '/analysis-jobs/job-1') body = { id: 'job-1', dataset_id: datasetId, name: 'C2 layout fixture', status: 'COMPLETED', candidate_count: 0, analysis: { module: 'c2' } };
    else if (path === '/analysis-jobs/job-1/ai-runs') body = { items: [run], total: 1 };
    else if (path === '/ai-runs/layout-run') body = run;
    else if (path === '/ai-capabilities') body = { available: true, remote: false, provider: 'fixture', model_name: 'layout-only' };
    else if (path === '/ai-runs/layout-run/assessments' || path === '/analysis-jobs/job-1/candidates' || path === '/sensor-pcaps') body = { items: [], total: 0 };
    else if (path === '/analysis-jobs/job-1/flows') body = { items: [], total: 0, page: 1, page_size: 50 };
    else if (path === '/ai-runs/layout-run/selection') {
      const offset = Number(url.searchParams.get('offset'));
      expect(url.searchParams.get('limit')).toBe('20');
      body = {
        items: Array.from({ length: offset === 0 ? 20 : 1 }, (_, index) => ({
          candidate_id: `layout-candidate-${offset + index}`, external_ip: ips[index % ips.length],
          origin: origins[index % origins.length], existing_score: index % 2 ? 0 : 85,
          anomaly_score: index % 2 ? 0.987654 : null, selected: offset + index < 3,
          reason: offset + index < 2 ? 'DISCOVERY_RESERVED' : offset + index === 2 ? 'RANKED' : 'BUDGET_LIMIT',
        })), total: 21, offset, limit: 20, next_offset: offset === 0 ? 20 : null,
      };
    } else return route.fallback();
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify(body) });
  });
}

async function expectWithinViewport(locator: Locator) {
  const bounds = await locator.evaluate(element => {
    const rect = element.getBoundingClientRect();
    return { left: rect.left, right: rect.right, viewport: document.documentElement.clientWidth };
  });
  expect(bounds.left).toBeGreaterThanOrEqual(0);
  expect(bounds.right).toBeLessThanOrEqual(bounds.viewport + 1);
}

async function expectPageFits(page: Page) {
  const geometry = await page.evaluate(() => ({
    viewport: window.innerWidth, body: document.body.scrollWidth, document: document.documentElement.scrollWidth,
  }));
  expect(geometry.body, JSON.stringify(geometry)).toBeLessThanOrEqual(geometry.viewport);
  expect(geometry.document, JSON.stringify(geometry)).toBeLessThanOrEqual(geometry.viewport);
}

for (const width of [1280, 390]) {
  test(`shadow inventory scrolls locally without clipping at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await installSelectionFixture(page);
    await page.goto('/login');
    await page.getByLabel('Username').fill('analyst');
    await page.getByRole('button', { name: 'Development login' }).click();
    await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
    await page.goto('/analyses/job-1');
    await page.getByLabel('보고서 언어 / Report language').selectOption('en');
    const coverage = page.getByRole('region', { name: 'Discovery coverage' });
    const toggle = coverage.getByRole('button', { name: 'View selection inventory' });
    await expect(toggle).toBeVisible();
    const datasetDescription = page.locator('.panel.compact > p').filter({ hasText: datasetId });
    await expect(datasetDescription).toContainText(datasetId);
    expect(await datasetDescription.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
    await expectPageFits(page);
    await toggle.click();
    const table = coverage.getByRole('table', { name: 'Selection inventory' });
    await expect(table.locator('tbody tr')).toHaveCount(20);
    const wrap = coverage.locator('.table-wrap');
    const geometry = await wrap.evaluate(element => ({
      client: element.clientWidth, scroll: element.scrollWidth,
      body: document.body.scrollWidth, viewport: window.innerWidth,
      contentMinWidth: getComputedStyle(document.querySelector('.content')!).minWidth,
      shellColumns: getComputedStyle(document.querySelector('.shell')!).gridTemplateColumns,
    }));
    console.log(`inventory layout ${width}: ${JSON.stringify(geometry)}`);
    await testInfo.attach('layout', { body: JSON.stringify(geometry), contentType: 'application/json' });
    await expectPageFits(page);
    await expectWithinViewport(coverage);
    await expectWithinViewport(wrap);
    for (const text of [
      'Candidate pool 21 · Selected 3 · Omitted 18',
      'Discovery candidates 2 · Discovery selected 2 · Rule-free selected 1 · Reserved slots 2',
      'This is a budget-limited review, not complete traffic coverage. Omitted does not mean benign.',
    ]) {
      const paragraph = coverage.getByText(text, { exact: true });
      await expect(paragraph).toBeVisible();
      await expectWithinViewport(paragraph);
      expect(await paragraph.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
    }
    for (const ip of ips) await expect(table.getByRole('cell', { name: ip, exact: true }).first()).toHaveText(ip);
    for (const origin of origins) await expect(table.getByRole('cell', { name: origin, exact: true }).first()).toHaveText(origin);
    expect(geometry.scroll).toBeGreaterThan(geometry.client);
    expect(await wrap.evaluate(element => getComputedStyle(element).overflowX)).toBe('auto');
    await wrap.evaluate(element => { element.scrollLeft = element.scrollWidth; });
    expect(await wrap.evaluate(element => element.scrollLeft)).toBeGreaterThan(0);
    await expectWithinViewport(table.getByRole('columnheader', { name: 'Reason', exact: true }));
    await expectWithinViewport(table.getByRole('cell', { name: 'DISCOVERY_RESERVED', exact: true }).first());
    const identifierAccess = await wrap.evaluate(element => {
      element.scrollLeft = 0;
      const cell = element.querySelector('tbody td')!;
      const range = document.createRange();
      range.selectNodeContents(cell);
      const leftReachable = range.getBoundingClientRect().left >= element.getBoundingClientRect().left;
      const fragments = range.getClientRects().length;
      element.scrollLeft = range.getBoundingClientRect().right - element.getBoundingClientRect().right + 2;
      return { leftReachable, fragments, rightReachable: range.getBoundingClientRect().right <= element.getBoundingClientRect().right };
    });
    expect(identifierAccess).toEqual({ leftReachable: true, fragments: 1, rightReachable: true });
    const next = coverage.getByRole('button', { name: 'Next selection page' });
    const previous = coverage.getByRole('button', { name: 'Previous selection page' });
    for (const button of [toggle, next, previous]) await expectWithinViewport(button);
    await expect(previous).toBeDisabled();
    await next.click();
    await expect(coverage.locator('.ai-run-controls').getByRole('status')).toHaveText('Offset 20 · 1 of 21 candidates');
    await expect(next).toBeDisabled();
    await previous.click();
    await expect(coverage.locator('.ai-run-controls').getByRole('status')).toHaveText('Offset 0 · 20 of 21 candidates');
    await expectPageFits(page);
    await toggle.click();
    await expect(table).toHaveCount(0);
    await expectPageFits(page);
    expect(errors).toEqual([]);
  });
}
