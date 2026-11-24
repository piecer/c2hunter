import { withLegacyAuthentication } from './auth-fixture';
import { expect, test, type Page } from '@playwright/test';
import { installApiFixture } from './route-fixture';

// Transport fixtures follow _dashboard_snapshot's 5/8/5/24 bounds; no live model or sensor.
const dashboard = {
  generated_at: '2026-11-17T00:00:00Z',
  fleet: { total: 5, online: 3, offline: 1, degraded: 1, dropped_packets: 1234 },
  analyses: { total: 9, active: 2, completed_24h: 3, failed_24h: 1, partially_completed_24h: 2, by_status: { ANALYZING: 2 } },
  candidates: { total: 20, communication_status: 3, critical: 5, high: 5, medium: 5, low: 5, new_24h: 4, needs_review: 7, in_review: 4, action_required: 3, action_in_progress: 2, action_completed: 2, false_positive: 2, done: 4 },
  priority_candidates: Array.from({ length: 5 }, (_, index) => ({ id: `queue-${index}`, job_id: 'job-1', candidate_ip: `203.0.113.${index + 20}`, candidate_kind: 'C2', score: 90 - index, severity: 'HIGH', evidence_count: index + 1, last_seen: '2026-11-16T23:59:00Z', workflow_status: ['NEEDS_REVIEW', 'IN_REVIEW', 'ACTION_REQUIRED', 'ACTION_IN_PROGRESS', 'NEEDS_REVIEW'][index] })),
  attention: Array.from({ length: 8 }, (_, index) => ({ kind: 'OFFLINE_SENSOR', severity: 'HIGH', title: `수집 확인 ${index + 1}`, detail: `관측이 누락되어 개별 센서 heartbeat 확인 필요 ${index + 1}`, href: '/sensors/sensor-a' })),
  sensor_quality: Array.from({ length: 5 }, (_, index) => ({ sensor_id: `sensor-${index}`, name: `수집 센서 ${index}`, status: 'DEGRADED', received_packets: 10000, dropped_packets: 200, drop_rate_percent: 2, last_heartbeat_at: '2026-11-16T23:00:00Z', last_error: 'capture incomplete' })),
  recent_analyses: Array.from({ length: 5 }, (_, index) => ({ id: `job-${index}`, name: `Recent analysis ${index}`, status: 'PARTIALLY_COMPLETED', candidate_count: 2, packet_count: 300, flow_count: 20, created_at: '2026-11-16T23:00:00Z' })),
  candidate_trend: Array.from({ length: 24 }, (_, index) => ({ hour: `2026-11-16T${String(index).padStart(2, '0')}:00:00Z`, count: index % 3 })),
};

async function geometry(page: Page, width: number, limit: number) {
  const measured = await page.evaluate(() => ({ nodes: document.querySelectorAll('*').length, documentWidth: document.documentElement.scrollWidth, bodyWidth: document.body.scrollWidth,
    overflow: [...document.querySelectorAll('main, main > *, .dashboard > *, .dashboard .panel, nav')].map(element => ({ element: `${element.tagName}.${element.className}`, x: element.getBoundingClientRect().x, right: element.getBoundingClientRect().right, minWidth: getComputedStyle(element).minWidth })).filter(box => box.right > innerWidth),
  }));
  expect(measured.nodes).toBeLessThanOrEqual(limit);
  expect(measured.documentWidth, JSON.stringify(measured)).toBeLessThanOrEqual(width);
  expect(measured.bodyWidth).toBeLessThanOrEqual(width);
  return measured;
}

for (const width of [1280, 390]) {
  test(`Dashboard exposes real limits and review before charts at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    await page.addInitScript(() => localStorage.setItem('c2hunter-token', 'test'));
    const requests: string[] = [];
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await installApiFixture(page);
    await page.route('**/api/v1/**', withLegacyAuthentication(async route => {
      const path = new URL(route.request().url()).pathname;
      requests.push(`${route.request().method()} ${path}`);
      if (path === '/api/v1/dashboard') return route.fulfill({ json: dashboard });
      if (path === '/api/v1/candidates/queue-0') return route.fulfill({ json: dashboard.priority_candidates[0] });
      return route.fallback();
    }));
    await page.goto('/');
    const trust = page.getByRole('region', { name: '집계 범위 및 수집 제한' });
    await expect(trust).toContainText('오프라인 1 · 성능 저하 1 · 누락 패킷 1,234');
    await expect(trust).toContainText('최근 24시간 부분 완료 2건 · 실패 1건');
    await expect(trust).toContainText('집계 시각은 개별 관측의 최신성을 보장하지 않습니다.');
    await expect(page.locator('.dashboard-updated time')).toHaveAttribute('datetime', dashboard.generated_at);
    const queue = page.getByRole('list', { name: '분석 및 조치 필요 후보' });
    await expect(queue.getByRole('link')).toHaveCount(5);
    await expect(queue).toContainText('조치 중');
    await expect(page.locator('.attention-panel li')).toHaveCount(8);
    await expect(page.getByRole('region', { name: '운영 핵심 지표' }).locator('article')).toHaveCount(7);
    const chart = page.getByRole('img', { name: '최근 24시간 시간별 신규 후보' });
    const chartBox = await chart.boundingBox();
    const boxes = [];
    for (const target of [page.locator('.dashboard-updated'), trust, page.getByRole('heading', { name: '분석 및 조치 필요 후보' }), queue.getByRole('link').first()]) {
      const box = await target.boundingBox();
      expect(box).not.toBeNull();
      expect(box!.y).toBeGreaterThanOrEqual(0);
      expect(box!.y + box!.height).toBeLessThanOrEqual(900);
      expect(box!.y + box!.height).toBeLessThan(chartBox!.y);
      boxes.push(box);
    }
    const initial = await geometry(page, width, 1200);
    expect(requests).toEqual(['GET /api/v1/dashboard']);
    await page.screenshot({ path: testInfo.outputPath('dashboard-initial.png'), fullPage: true });
    for (const link of await page.locator('.dashboard-list a').all()) {
      await link.focus();
      await expect(link).toBeFocused();
    }
    await chart.scrollIntoViewIfNeeded();
    await expect(chart).toBeInViewport();
    const sequential = await geometry(page, width, 2500);
    await queue.getByRole('link').first().focus();
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/\/candidates\/queue-0$/);
    await expect(page.getByRole('heading', { name: '203.0.113.20', exact: true })).toBeVisible();
    expect(requests.filter(request => !request.startsWith('GET '))).toEqual([]);
    expect(errors).toEqual([]);
    await testInfo.attach('geometry-and-requests', { body: JSON.stringify({ initial, sequential, boxes, requests }), contentType: 'application/json' });
  });

  test(`Primary and management entries stay keyboard reachable at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    await page.addInitScript(() => localStorage.setItem('c2hunter-token', 'test'));
    await installApiFixture(page);
    const writes: string[] = [];
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => { if (request.url().includes('/api/v1/') && request.method() !== 'GET') writes.push(request.url()); });
    // Start on a management deep link, not a dashboard redirect.
    await page.goto('/settings/integrations');
    await expect(page.getByRole('heading', { name: 'Threat intelligence & MISP', exact: true })).toBeVisible();
    await page.waitForLoadState('networkidle');
    const menu = page.getByRole('button', { name: '메뉴 / Menu' });
    const primary = page.getByRole('navigation', { name: 'Primary', exact: true });
    const management = page.getByRole('navigation', { name: 'Management', exact: true });
    const snapshots = [{ route: '/settings/integrations', ...await geometry(page, width, 1200) }];
    if (width === 390) {
      await expect(primary).toBeHidden();
      await menu.focus();
      await page.keyboard.press('Enter');
      await expect(menu).toHaveAttribute('aria-expanded', 'true');
      await management.getByRole('link', { name: 'Integration settings', exact: true }).focus();
      await page.keyboard.press('Escape');
      await expect(menu).toBeFocused();
      await expect(menu).toHaveAttribute('aria-expanded', 'false');
    }
    const groups = [
      { nav: primary, paths: ['/', '/candidates', '/analyses', '/analyses/new', '/analyses/upload', '/sensor-pcaps'] },
      { nav: management, paths: ['/sensors', '/external-sensors', '/external-sensors/enroll', '/payload-signatures', '/allowlist', '/settings/integrations'] },
    ];
    const headings: Record<string, string> = {
      '/': 'Dashboard', '/candidates': 'Candidates', '/analyses': 'Analysis history',
      '/analyses/new': 'New analysis', '/analyses/upload': 'Upload PCAP', '/sensor-pcaps': 'Sensor PCAPs',
      '/sensors': 'Sensors', '/external-sensors': 'External sensors', '/external-sensors/enroll': 'Enroll sensor',
      '/payload-signatures': 'Payload signatures', '/allowlist': 'Exceptions and infrastructure policies',
      '/settings/integrations': 'Threat intelligence & MISP',
    };
    for (const { nav, paths } of groups) {
      if (width === 390) await menu.click();
      expect(await nav.getByRole('link').evaluateAll(links => links.map(link => link.getAttribute('href')))).toEqual(paths);
      // Labels must occupy their own row, not displace a link into a heading column.
      const label = await nav.getByRole('heading').boundingBox();
      const first = await nav.getByRole('link').first().boundingBox();
      expect(label!.y + label!.height).toBeLessThanOrEqual(first!.y);
      if (width === 390) await menu.click();
      for (const path of paths) {
        if (width === 390) await menu.click();
        const link = nav.locator(`a[href="${path}"]`);
        await link.focus();
        await expect(link).toBeFocused();
        await expect(link).toBeInViewport();
        await page.keyboard.press('Enter');
        await expect(page).toHaveURL(new RegExp(`${path.replaceAll('/', '\\/')}$`));
        await expect(page.getByRole('heading', { name: headings[path], exact: true, level: 1 })).toBeVisible();
        await page.waitForLoadState('networkidle');
        await expect(page.locator('main .loading')).toHaveCount(0);
        if (width === 390) {
          await expect(menu).toBeFocused();
          await expect(menu).toHaveAttribute('aria-expanded', 'false');
        }
        snapshots.push({ route: path, ...await geometry(page, width, 2500) });
      }
    }
    expect(writes).toEqual([]);
    expect(errors).toEqual([]);
    await testInfo.attach('route-geometry', { body: JSON.stringify(snapshots), contentType: 'application/json' });
  });
}
