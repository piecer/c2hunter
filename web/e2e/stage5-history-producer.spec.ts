import { withLegacyAuthentication } from './auth-fixture';
import { expect, test } from '@playwright/test';
import { historyListing, historyProducer, historyUnavailable } from '../tests/stage5HistoryFixture';
import { installApiFixture } from './route-fixture';

for (const width of [1280, 390]) test(`Real DDoS list availability and opaque detail/Back at ${width}`, async ({ page }, info) => {
  await page.setViewportSize({ width, height: 900 });
  await page.addInitScript(() => {
    localStorage.setItem('c2hunter-token', 'test');
    localStorage.setItem('c2hunter-report-language', 'en');
  });
  const errors: string[] = [], writes: string[] = [], detailReads: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await installApiFixture(page);
  await page.route('**/api/v1/**', withLegacyAuthentication(async route => {
    const request = route.request(), url = new URL(request.url());
    if (request.method() !== 'GET') { writes.push(url.pathname); return route.abort(); }
    if (url.pathname === '/api/v1/analysis-jobs') {
      expect(url.searchParams.get('search')).toBe('Producer limited DDoS');
      expect(url.searchParams.get('status')).toBe('COMPLETED');
      expect(url.searchParams.get('sort')).toBe('name');
      expect(url.searchParams.get('page')).toBe('1');
      return route.fulfill({ contentType: 'application/json', body: historyProducer.list_wire });
    }
    if (url.pathname === historyProducer.detail_path) {
      detailReads.push(url.pathname);
      return route.fulfill({ contentType: 'application/json', body: historyProducer.detail_wire });
    }
    return route.fallback();
  }));
  const listURL = '/analyses?search=Producer%20limited%20DDoS&status=COMPLETED&sort=name&page=1';
  await page.goto(listURL);
  const produced = historyListing.items[0];
  const row = page.getByRole('table', { name: 'Analysis history' }).getByRole('row').nth(1);
  await expect(row).toContainText(`${produced.ddos_attack_summary.finding_count} DDoS findings`);
  await expect(row).toContainText('Coverage incomplete');
  for (const warning of produced.warnings) await expect(row).toContainText(warning);
  await expect(row.getByText(historyUnavailable, { exact: true })).toBeVisible();
  await expect(row).not.toContainText('Counts are lower bounds');
  const invoker = row.getByRole('link', { name: produced.name, exact: true });
  await invoker.scrollIntoViewIfNeeded();
  await invoker.focus();
  const top = await page.evaluate(() => scrollY);
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(url => url.pathname === `/analyses/${encodeURIComponent(produced.id)}`);
  await expect(page.getByRole('heading', { name: produced.name, exact: true })).toBeVisible();
  await expect(page.getByText('Coverage is incomplete; Counts are lower bounds — not a clean result.', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Analysis coverage and limitations', exact: true }).click();
  await expect(page.getByRole('region', { name: 'DDoS analysis coverage' })).toContainText('Counts are lower bounds; retained evidence is truncated or incomplete.');
  expect(detailReads).toContain(historyProducer.detail_path);
  await page.goBack();
  await expect(page).toHaveURL(url => url.pathname + url.search === listURL);
  await expect(page.getByLabel('Search', { exact: true })).toHaveValue('Producer limited DDoS');
  await expect(page.getByRole('combobox', { name: 'Status', exact: true })).toHaveValue('COMPLETED');
  await expect(page.getByLabel('Sort analyses')).toHaveValue('name');
  await expect(invoker).toBeFocused();
  await expect.poll(() => page.evaluate(() => scrollY)).toBe(top);
  await expect(row.getByText(historyUnavailable, { exact: true })).toBeVisible();
  expect(writes).toEqual([]); expect(errors).toEqual([]);
  await info.attach('public-list-detail-provenance', { body: JSON.stringify({ ...historyProducer, detailReads }), contentType: 'application/json' });
});
