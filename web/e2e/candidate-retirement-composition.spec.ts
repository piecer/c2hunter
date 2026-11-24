import { withLegacyAuthentication } from './auth-fixture';
import { expect, test } from '@playwright/test';

const candidate = { id: 'composition-a', job_id: 'job-a', candidate_ip: '203.0.113.9', score: 80, severity: 'HIGH', evidence: [{ type: 'PERIODIC_BEACON', description: 'Retained reason', warnings: ['Limited coverage'] }] };

for (const section of ['operations', 'evidence', 'flows']) test(`global preview deletion retires canonical ${section} within production freshness`, async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  let missing = false;
  const writes: string[] = [];
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => localStorage.setItem('c2hunter-token', 'composition'));
  await page.route('**/api/v1/**', withLegacyAuthentication(async route => {
    const path = new URL(route.request().url()).pathname;
    if (route.request().method() !== 'GET') writes.push(path);
    if (path === '/api/v1/candidates') return route.fulfill({ json: { items: [candidate], total: 1, page: 1, page_size: 50 } });
    if (path.includes('/flows')) return route.fulfill({ json: { items: [{ flow_id: 'flow-a', job_id: 'job-a', timestamp: '2026-11-15T00:00:00Z', source_ip: '10.0.0.1', destination_ip: candidate.candidate_ip, protocol: 'TCP', direction: 'OUTBOUND', has_payload: true }], total: 1, page: 1, page_size: 50 } });
    if (missing) return route.fulfill({ status: 404, json: { error: { code: 'CANDIDATE_NOT_FOUND', message: 'Missing source' } } });
    return route.fulfill({ json: candidate });
  }));
  await page.goto(`/candidates/composition-a?detail=${section}${section === 'evidence' ? '&evidence=0' : section === 'flows' ? '&flow_page=1&flow=flow-a' : ''}`);
  if (section === 'evidence') await expect(page.locator('.evidence.detailed')).toContainText('Retained reason');
  else await expect(page.getByRole('button', { name: section === 'flows' ? 'Mark benign flow-a' : 'Delete candidate', exact: true })).toBeVisible();
  const started = await page.evaluate(() => performance.now());

  await page.getByRole('link', { name: 'Candidates', exact: true }).click();
  missing = true;
  await page.getByRole('button', { name: `Preview candidate ${candidate.candidate_ip}` }).click();
  await expect(page.getByText(/Selected candidate unavailable in this scope/)).toBeVisible();
  await page.goBack(); await page.goBack();
  await expect(page.getByRole('heading', { name: candidate.candidate_ip, exact: true })).toBeVisible();
  expect(await page.evaluate(() => performance.now()) - started).toBeLessThan(10_000);
  // Immediate assertion: a polling timeout must not age a stale successful cache.
  expect(await page.getByRole('button', { name: 'Delete candidate', exact: true }).count()).toBe(0);
  expect(await page.getByRole('button', { name: 'Mark benign flow-a', exact: true }).count()).toBe(0);
  expect(await page.locator('.evidence.detailed').count()).toBe(0);
  await expect(page.getByText(/Candidate unavailable; retained summary is historical/)).toBeVisible();
  await expect(page.getByRole('button', { name: '점수 조정 및 작업', exact: true })).toBeDisabled();
  expect(await page.getByRole('button', { name: 'Delete candidate', exact: true }).count()).toBe(0);
  missing = false;
  await page.getByRole('button', { name: 'Retry candidate', exact: true }).click();
  await expect(page.getByRole('button', { name: '점수 조정 및 작업', exact: true })).toBeEnabled();
  expect(await page.getByRole('button', { name: 'Delete candidate', exact: true }).count()).toBe(0);
  expect(await page.getByRole('button', { name: 'Mark benign flow-a', exact: true }).count()).toBe(0);
  expect(await page.locator('.evidence.detailed').count()).toBe(0);
  await page.getByRole('button', { name: '점수 조정 및 작업', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Delete candidate', exact: true })).toBeEnabled();
  await page.goBack();
  expect(await page.getByRole('button', { name: 'Delete candidate', exact: true }).count()).toBe(0);
  expect(writes).toEqual([]); expect(errors).toEqual([]);
});

for (const control of ['transient 503', 'wrong job membership', 'unrelated candidate B']) test(`${control} preserves canonical A history within production freshness`, async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.addInitScript(() => localStorage.setItem('c2hunter-report-language', 'en'));
  await page.addInitScript(() => localStorage.setItem('c2hunter-token', 'composition'));
  let missing = false;
  const writes: string[] = [];
  const b = { ...candidate, id: 'composition-b', candidate_ip: '203.0.113.10' };
  await page.route('**/api/v1/**', withLegacyAuthentication(async route => {
    const path = new URL(route.request().url()).pathname;
    if (route.request().method() !== 'GET') writes.push(path);
    if (path === '/api/v1/analysis-jobs/job-a') return route.fulfill({ json: { id: 'job-a', name: 'Scoped fixture', status: 'COMPLETED', analysis: { module: 'c2' }, candidate_count: 1 } });
    if (path === '/api/v1/candidates' || path === '/api/v1/analysis-jobs/job-a/candidates') return route.fulfill({ json: { items: [candidate, b], total: 2, page: 1, page_size: 50 } });
    if (missing && (control === 'transient 503' || path.includes('/analysis-jobs/') || path.endsWith('/composition-b'))) return route.fulfill({ status: control === 'transient 503' ? 503 : 404, json: { error: { code: control === 'transient 503' ? 'UNAVAILABLE' : 'CANDIDATE_NOT_FOUND' } } });
    return route.fulfill({ json: candidate });
  }));
  await page.goto('/candidates/composition-a?detail=operations');
  await expect(page.getByRole('button', { name: 'Delete candidate', exact: true })).toBeVisible();
  const started = await page.evaluate(() => performance.now());
  if (control === 'wrong job membership') await page.getByRole('link', { name: 'View source analysis' }).click();
  else await page.getByRole('link', { name: 'Candidates', exact: true }).click();
  // The scoped list may be stale after membership changes, as in production.
  const trigger = page.getByRole('button', { name: `Preview candidate ${control === 'unrelated candidate B' ? b.candidate_ip : candidate.candidate_ip}`, exact: true });
  await expect(trigger).toBeVisible(); missing = true;
  await trigger.click();
  await expect(page.getByText(control === 'transient 503' ? /Candidate preview could not be refreshed/ : /Selected candidate unavailable in this scope/)).toBeVisible();
  await page.goBack(); await page.goBack();
  await expect(page.getByRole('button', { name: 'Delete candidate', exact: true })).toBeEnabled();
  expect(await page.evaluate(() => performance.now()) - started).toBeLessThan(10_000);
  expect(writes).toEqual([]);
});
