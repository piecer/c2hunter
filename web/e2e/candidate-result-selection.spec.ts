import { withLegacyAuthentication } from './auth-fixture';
import { expect, test } from '@playwright/test';
import { installApiFixture } from './route-fixture';

const id = `candidate-${'abcdef0123456789'.repeat(16)}/part?query#fragment%`;
const encodedId = encodeURIComponent(id);
const candidate = {
  id, job_id: 'job-1', candidate_ip: '2001:db8:abcd:1234:5678:90ab:cdef:1234', score: 87, severity: 'HIGH',
  workflow_status: 'NEEDS_REVIEW', action_status: 'NOT_REQUIRED',
  hosts: ['10.0.0.5'], sensors: ['sensor-a'], protocols: ['TCP'], ports: [443], domains: ['retained.example'],
  first_seen: '2026-11-15T00:00:00Z', last_seen: '2026-11-15T00:01:00Z', flow_count: 600, packet_count: 6000, byte_count: 65536,
  ti_assessment: { status: 'PARTIAL', signal: 'INCOMPLETE', configured_providers: 3, successful_providers: 1, positive_providers: 0, virustotal_malicious: 0, virustotal_suspicious: 0, abuse_confidence_score: 0, misp_event_count: 0 },
  threat_intelligence: { status: 'PARTIAL', providers: { misp: { status: 'ERROR', error: 'Fixture provider unavailable' } }, summary: {} },
  current_verdict: { id: 'verdict-a', verdict: 'UNDER_REVIEW', confidence: 'LOW', note: 'Analyst observation '.repeat(50), created_at: '2026-11-15T00:01:00Z', created_by: 'analyst' },
  verdict_history: [{ id: 'verdict-a', verdict: 'UNDER_REVIEW', confidence: 'LOW', note: 'Retained historical note '.repeat(100), created_at: '2026-11-15T00:01:00Z', created_by: 'analyst' }],
  traffic_buckets: Array.from({ length: 600 }, (_, i) => ({ start: new Date(Date.UTC(2026, 10, 15, 0, i)).toISOString(), flows: i, packets: 10, bytes: 256 })),
  evidence: Array.from({ length: 30 }, (_, i) => ({ type: 'PERIODIC_BEACON', description: `Retained reason ${i + 1}`, raw_score: i, warnings: i === 29 ? ['Evidence coverage is incomplete'] : [],
    metrics: { sample_count: 600, period_seconds: 30, observations: Array.from({ length: 100 }, (_, j) => `observation-${j}-${'x'.repeat(180)}`), nested: { full_identifier: 'z'.repeat(500), samples: Array.from({ length: 100 }, (_, j) => ({ id: j, value: null })) } },
  })),
  adjustments: [{ kind: 'LOW_SAMPLE', points: -5, explanation: 'Preserve this adjustment' }],
};
for (const width of [1280, 390]) {
  test(`standalone candidate owns one bounded detail at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    const errors: string[] = []; const writes: string[] = []; const reads: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await installApiFixture(page);
    await page.route('**/api/v1/**', withLegacyAuthentication(async route => {
      const path = new URL(route.request().url()).pathname.replace('/api/v1', '');
      if (route.request().method() === 'GET') reads.push(path);
      else if (path !== '/auth/dev-login') writes.push(path);
      if (path === `/candidates/${encodedId}`) return route.fulfill({ json: candidate });
      return route.fallback();
    }));
    await page.goto('/login');
    await page.getByLabel(/^(Username|사용자 이름)$/).fill('analyst');
    await page.getByRole('button', { name: /^(Development login|개발 로그인)$/ }).click();
    await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
    await page.waitForLoadState('networkidle'); reads.length = 0;
    await page.goto(`/candidates/${encodedId}`);
    const summary = page.getByRole('region', { name: 'Candidate result summary' });
    await expect(summary).toBeVisible(); await page.waitForLoadState('networkidle');
    expect(reads).toEqual([`/candidates/${encodedId}`]);
    const measurements: unknown[] = [];
    const measure = async (limit: number) => {
      const geometry = await page.evaluate(() => ({ count: document.querySelectorAll('*').length, documentWidth: document.documentElement.scrollWidth, bodyWidth: document.body.scrollWidth }));
      measurements.push(geometry);
      expect(geometry.count).toBeLessThanOrEqual(limit);
      expect(geometry.documentWidth).toBeLessThanOrEqual(width);
      expect(geometry.bodyWidth).toBeLessThanOrEqual(width);
    };
    await measure(1200);
    await page.screenshot({ path: testInfo.outputPath('candidate-overview.png'), fullPage: true });
    for (const target of [summary.getByText('Evidence coverage is incomplete'), summary.getByText(/다음 확인:/)]) {
      const box = await target.boundingBox(); expect(box!.y + box!.height).toBeLessThanOrEqual(900);
    }
    await expect(summary.locator('li')).toHaveCount(3);
    await expect(page.getByRole('table', { name: 'Candidate traffic buckets' })).toHaveCount(0);
    const opener = page.getByRole('button', { name: '근거 1 · 주기적 비콘', exact: true });
    await opener.click();
    const surface = page.getByRole(width < 1200 ? 'dialog' : 'region', { name: 'Selected candidate detail' });
    await expect(surface.getByRole('heading', { name: 'Selected candidate detail', exact: true })).toBeFocused();
    if (width < 1200) await expect(surface).toHaveAttribute('aria-modal', 'true');
    const metrics = surface.locator('details.evidence-metric-details');
    await expect(metrics.locator(':scope > *')).toHaveCount(1);
    if (width < 1200) {
      await page.keyboard.press('Shift+Tab');
      await expect(metrics.locator('summary')).toBeFocused();
      await page.keyboard.press('Tab');
      await expect(surface.getByRole('button', { name: 'Close candidate detail' })).toBeFocused();
    }
    await metrics.locator('summary').click();
    await expect(surface.getByText(/^observation-0-/)).toBeVisible();
    for (let i = 0; i < 4; i++) await surface.getByRole('button', { name: 'Next metric values' }).click();
    await expect(surface.getByText(/^observation-99-/)).toBeVisible();
    await measure(2500);
    await surface.getByLabel('상세 지표 선택').selectOption('nested');
    await expect(surface.locator('.metric-detail pre')).toContainText('"id": 99');
    await expect(surface.locator('.metric-detail pre')).toContainText('z'.repeat(500));
    await measure(2500);
    await metrics.locator('summary').click();
    await expect(metrics.locator(':scope > *')).toHaveCount(1);
    await page.keyboard.press('Escape');
    await expect(opener).toBeFocused();
    await expect(page.locator('.evidence.detailed')).toHaveCount(0);
    await measure(1200);
    await page.getByRole('button', { name: 'Traffic buckets', exact: true }).click();
    await measure(2500);
    await expect(page.getByRole('table', { name: 'Candidate traffic buckets' }).locator('tbody tr')).toHaveCount(50);
    for (let i = 0; i < 11; i++) await page.getByRole('button', { name: 'Next traffic buckets' }).click();
    await expect(page.getByText('Buckets 551–600 of 600')).toBeVisible();
    await measure(2500);
    await page.keyboard.press('Escape');
    await page.getByRole('button', { name: '판정 및 외부 검증', exact: true }).click();
    await expect(page.getByText('Fixture provider unavailable')).toBeVisible();
    await measure(2500);
    await page.screenshot({ path: testInfo.outputPath('candidate-detail.png'), fullPage: true });
    await page.getByRole('button', { name: 'Close candidate detail' }).click();
    await page.getByRole('button', { name: '점수 조정 및 작업', exact: true }).click();
    await page.getByRole('button', { name: 'Delete candidate', exact: true }).click();
    const deletion = page.getByRole('dialog', { name: 'Delete candidate permanently' });
    await expect(deletion).toBeVisible();
    await deletion.getByRole('button', { name: 'Cancel', exact: true }).click();
    await expect(deletion).toHaveCount(0);
    expect(errors).toEqual([]); expect(writes).toEqual([]);
    await testInfo.attach('candidate-geometry', { body: JSON.stringify(measurements), contentType: 'application/json' });
  });
}
