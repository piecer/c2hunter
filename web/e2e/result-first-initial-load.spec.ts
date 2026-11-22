import { expect, test } from '@playwright/test';
import { installApiFixture } from './route-fixture';

// Generated transport fixtures, not a deployed worker/model acceptance claim.
const candidates = Array.from({ length: 51 }, (_, index) => ({
  id: `result-first-candidate-${index + 1}`, job_id: 'result-first-job',
  candidate_ip: `203.0.113.${index + 1}`, score: 80, severity: 'HIGH',
  workflow_status: 'NEEDS_REVIEW', action_status: 'NOT_REQUIRED',
  hosts: ['10.0.0.5'], sensors: ['sensor-a'], protocols: ['TCP'], ports: [443],
  evidence_count: 2, first_seen: '2026-11-15T00:00:00Z', last_seen: '2026-11-15T00:01:00Z',
}));

for (const { width, language } of [1280, 390].flatMap(width => ['ko', 'en'].map(language => ({ width, language })))) {
  test(`C2 opens only bounded results before optional work at ${width}px in ${language}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    await page.addInitScript(value => localStorage.setItem('c2hunter-report-language', value), language);
    const errors: string[] = [];
    const writes: string[] = [];
    const reads: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await installApiFixture(page);
    await page.route('**/api/v1/**', async route => {
      const request = route.request();
      const url = new URL(request.url());
      const path = url.pathname.replace('/api/v1', '');
      if (request.method() !== 'GET' && path !== '/auth/dev-login') writes.push(path);
      if (request.method() === 'GET') reads.push(path);
      let body: unknown;
      if (path === '/analysis-jobs/result-first-job') body = {
        id: 'result-first-job', dataset_id: 'result-first-dataset',
        name: 'C2 result with retained capture metadata', status: 'COMPLETED', source_type: 'PCAP_UPLOAD',
        description: 'Synthetic analyst note must remain accessible without displacing the result. '.repeat(8),
        processing: { phase: 'COMPLETED', phase_started_at: '2026-11-15T00:01:02Z' },
        source: { filename: 'synthetic-results.pcap', size_bytes: 65536, captured_packet_count: 2000, parsed_packet_count: 1000, skipped_packet_count: 1000, sha256: 'a'.repeat(64) },
        warnings: ['Fixture coverage limitation: some packets were not parsed.'],
        packet_count: 1000, flow_count: 61, candidate_count: candidates.length,
        sensor_ids: ['sensor-a'], internal_networks: ['10.0.0.0/8'],
        start_time: '2026-11-15T00:00:00Z', end_time: '2026-11-15T00:01:00Z',
        analysis: { module: 'c2', minimum_candidate_score: 20 },
        transitions: [{ to_status: 'COMPLETED', occurred_at: '2026-11-15T00:01:02Z', reason: 'Fixture complete' }],
      };
      else if (path === '/analysis-jobs/result-first-job/candidates') {
        const current = Number(url.searchParams.get('page') ?? '1');
        const size = Number(url.searchParams.get('page_size') ?? '50');
        body = { items: candidates.slice((current - 1) * size, current * size), total: candidates.length, page: current, page_size: size,
          workflow_counts: { needs_review: 51, in_review: 0, action_required: 0, action_in_progress: 0, action_completed: 0, false_positive: 0, done: 0 } };
      } else return route.fallback();
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify(body) });
    });
    await page.goto('/login');
    await page.getByLabel('Username').fill('analyst');
    await page.getByRole('button', { name: 'Development login' }).click();
    await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
    await page.waitForLoadState('networkidle');
    reads.length = 0;
    await page.goto('/analyses/result-first-job');
    await expect(page.getByRole('table', { name: 'Analysis candidates', exact: true })).toBeVisible();
    await page.waitForLoadState('networkidle');
    expect(reads).toEqual(['/analysis-jobs/result-first-job', '/analysis-jobs/result-first-job/candidates']);
    await expect(page.getByRole('table', { name: 'Analysis candidates', exact: true }).locator('tbody tr')).toHaveCount(25);
    await expect(page.getByText('Source and parsing', { exact: true })).toHaveCount(0);
    await expect(page.getByText('State transitions', { exact: true })).toHaveCount(0);
    await expect(page.getByText('Fixture coverage limitation: some packets were not parsed.', { exact: true })).toBeVisible();
    const summary = page.getByRole('region', { name: language === 'ko' ? 'C2 결과 요약' : 'C2 result summary', exact: true });
    const verdict = await summary.getByRole('heading').boundingBox();
    const nextCheck = await summary.getByRole('button', { name: language === 'ko' ? '후보 검토로 이동' : 'Review candidates', exact: true }).boundingBox();
    const limitation = await summary.getByText('Fixture coverage limitation: some packets were not parsed.', { exact: true }).boundingBox();
    for (const box of [verdict, nextCheck, limitation]) {
      expect(box).not.toBeNull();
      expect(box!.y).toBeGreaterThanOrEqual(0);
      expect(box!.y + box!.height).toBeLessThanOrEqual(900);
    }
    const geometry = await page.evaluate(() => ({ nodes: document.querySelectorAll('*').length, width: innerWidth, documentWidth: document.documentElement.scrollWidth, bodyWidth: document.body.scrollWidth }));
    expect(geometry.nodes).toBeLessThanOrEqual(1200);
    expect(geometry.documentWidth).toBeLessThanOrEqual(width);
    expect(geometry.bodyWidth).toBeLessThanOrEqual(width);
    expect(errors).toEqual([]);
    expect(writes).toEqual([]);
    await page.screenshot({ path: testInfo.outputPath('result-first-overview.png'), fullPage: true });
    await testInfo.attach('initial-geometry', { body: JSON.stringify({ ...geometry, verdict, nextCheck, limitation }), contentType: 'application/json' });
  });
}
