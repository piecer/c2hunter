import { expect, test } from '@playwright/test';
import { installApiFixture } from './route-fixture';

// Real application rendering with synthetic transport data, not production acceptance.
for (const width of [1440, 390]) {
  test(`task-oriented console hierarchy and keyboard access at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 960 });
    await page.addInitScript(() => localStorage.setItem('c2hunter-token', 'test'));
    await installApiFixture(page);
    const writes: string[] = [];
    const errors: string[] = [];
    page.on('request', request => {
      if (request.url().includes('/api/v1/') && request.method() !== 'GET') writes.push(request.url());
    });
    page.on('pageerror', error => errors.push(error.message));
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
    await expect(page.getByRole('list', { name: '분석 및 조치 필요 후보' })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath('dashboard.png'), fullPage: true });

    // These are computed presentation contracts, not a stylesheet string snapshot.
    const layout = await page.evaluate(() => {
      const bounds = (selector: string) => document.querySelector(selector)!.getBoundingClientRect().toJSON();
      const queue = document.querySelector('.dashboard-action-grid > article')!;
      const metrics = document.querySelector('.dashboard-metrics')!;
      return {
        queue: bounds('.dashboard-action-grid > article'),
        attention: bounds('.attention-panel'),
        queueBackground: getComputedStyle(queue).backgroundColor,
        metricSurface: getComputedStyle(metrics).backgroundColor,
        metricBackgrounds: [...metrics.children].map(item => getComputedStyle(item).backgroundColor),
        accentRails: [...metrics.children].map(item => getComputedStyle(item, '::before').content),
        pageWidth: document.documentElement.scrollWidth,
        contentWidth: document.querySelector('main')!.scrollWidth,
        contentClient: document.querySelector('main')!.clientWidth,
      };
    });
    await testInfo.attach('geometry', { body: JSON.stringify(layout), contentType: 'application/json' });
    expect(layout.metricBackgrounds).toEqual(Array(7).fill('rgba(0, 0, 0, 0)'));
    expect(layout.accentRails.every(value => value === 'none')).toBe(true);
    expect(layout.metricSurface).not.toBe('rgba(0, 0, 0, 0)');
    const recent = await page.getByRole('heading', { name: '최근 분석', exact: true }).boundingBox();
    const trend = await page.getByRole('img', { name: '최근 24시간 시간별 신규 후보' }).boundingBox();
    expect(recent!.y + recent!.height).toBeLessThan(trend!.y);
    await expect(page.getByRole('table', { name: '최근 분석', exact: true }).getByRole('link').first()).toHaveCSS('color', 'rgb(119, 216, 179)');
    if (width > 800) expect(layout.queue.width).toBeGreaterThan(layout.attention.width * 1.3);
    expect(layout.pageWidth).toBeLessThanOrEqual(width);
    expect(layout.contentWidth).toBeLessThanOrEqual(layout.contentClient);

    const limits = page.getByRole('region', { name: '집계 범위 및 수집 제한' });
    await expect(limits).toContainText('누락 패킷 4');
    await expect(limits).toContainText('개별 관측의 최신성을 보장하지 않습니다');
    await expect(page.getByRole('region', { name: '운영 핵심 지표' }).locator('article')).toHaveCount(7);
    const skip = page.getByRole('link', { name: '본문으로 건너뛰기 / Skip to content' });
    await skip.focus();
    await expect(skip).toBeInViewport();
    await page.keyboard.press('Enter');
    await expect(page.getByRole('main')).toBeFocused();
    await page.getByRole('list', { name: '분석 및 조치 필요 후보' }).getByRole('link').first().click();
    await expect(page).toHaveURL(/\/candidates\/candidate-1$/);
    expect(writes).toEqual([]);
    expect(errors).toEqual([]);
  });
}

test('source-analysis navigation uses a legible link on the dark inspector', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('c2hunter-token', 'test'));
  await installApiFixture(page);
  await page.goto('/candidates/candidate-1');
  const source = page.getByRole('link', { name: 'View source analysis' });
  await expect(source).toHaveCSS('color', 'rgb(119, 216, 179)');
  await source.click();
  await expect(page).toHaveURL(/\/analyses\/job-1$/);
});

test('loading and error stay legible and recovery keeps the same dashboard owner', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('c2hunter-token', 'test'));
  await installApiFixture(page);
  let unavailable = true;
  await page.route('**/api/v1/dashboard', async route => {
    if (unavailable) return route.fulfill({ status: 503, json: { detail: 'dashboard temporarily unavailable' } });
    return route.fallback();
  });
  await page.goto('/');
  const error = page.getByRole('alert').filter({ hasText: '데이터를 불러오지 못했습니다' });
  await expect(error).toBeVisible();
  await expect(error.getByRole('button', { name: '다시 시도' })).toBeEnabled();
  unavailable = false;
  await error.getByRole('button', { name: '다시 시도' }).click();
  await expect(page.getByRole('list', { name: '분석 및 조치 필요 후보' })).toBeVisible();
  await expect(error).toHaveCount(0);
});
