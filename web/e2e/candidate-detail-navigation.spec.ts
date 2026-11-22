import { expect, test } from '@playwright/test';
import { installApiFixture } from './route-fixture';

const id = `candidate-${'abcdef0123456789'.repeat(32)}/part?query#fragment%`;
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
  test(`full-metadata compact candidate navigation at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    const writes: string[] = []; const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await installApiFixture(page);
    await page.route('**/api/v1/**', async route => {
      const path = new URL(route.request().url()).pathname.replace('/api/v1', '');
      if (route.request().method() !== 'GET' && path !== '/auth/dev-login') writes.push(path);
      if (path === `/candidates/${encodedId}`) return route.fulfill({ json: candidate });
      return route.fallback();
    });
    await page.goto('/login');
    await page.getByLabel('Username').fill('analyst');
    await page.getByRole('button', { name: 'Development login' }).click();
    await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
    await page.goto(`/candidates/${encodedId}?q=retained&page=4`);
    const summary = page.getByRole('region', { name: 'Candidate result summary' });
    await expect(summary).toBeVisible();
    const navigation = page.getByRole('navigation', { name: 'Candidate detail selection' });
    expect(await navigation.getByRole('button').count()).toBeLessThanOrEqual(10);
    for (const target of [summary.getByText('Evidence coverage is incomplete'), summary.getByText(/다음 확인:/), navigation.getByRole('button').first()]) {
      const box = await target.boundingBox(); expect(box!.y).toBeGreaterThanOrEqual(0); expect(box!.y + box!.height).toBeLessThanOrEqual(900);
    }
    await expect(summary.locator('li')).toHaveCount(3);
    await expect(page.getByRole('img', { name: 'Traffic over time' })).toBeVisible();
    const census = async (limit: number) => {
      const result = await page.evaluate(() => ({ count: document.querySelectorAll('*').length, width: document.documentElement.scrollWidth, body: document.body.scrollWidth }));
      expect(result.count).toBeLessThanOrEqual(limit); expect(result.width).toBeLessThanOrEqual(width); expect(result.body).toBeLessThanOrEqual(width);
      await testInfo.attach(`geometry-${limit}`, { body: JSON.stringify(result), contentType: 'application/json' });
    };
    await census(1200);
    await page.screenshot({ path: testInfo.outputPath('compact-initial.png'), fullPage: true });
    const identifier = page.locator('details.candidate-identifier');
    await expect(identifier.locator(':scope > *')).toHaveCount(1);
    await identifier.locator('summary').click();
    await expect(identifier.locator('.record-id')).toHaveText(`Candidate ${id}`);
    await identifier.locator('summary').click();
    await expect(identifier.locator(':scope > *')).toHaveCount(1);
    await page.getByLabel('Evidence selection').selectOption('29');
    await expect(page.locator('.evidence.detailed')).toContainText('Retained reason 30');
    await expect(page).toHaveURL(/detail=evidence&evidence=29/);
    await census(2500);
    await page.keyboard.press('Escape');
    await expect(page.getByLabel('Evidence selection')).toBeFocused();
    await expect(page).toHaveURL(/\?q=retained&page=4$/);
    const reached: number[] = []; const sizes: number[] = [];
    for (let index = 0; index < candidate.evidence.length; index++) {
      await page.getByLabel('Evidence selection').selectOption(String(index));
      await expect(page.locator('.evidence.detailed > p').first()).toHaveText(`Retained reason ${index + 1}`);
      reached.push(index);
      sizes.push(await page.evaluate(() => document.querySelectorAll('*').length));
      await page.keyboard.press('Escape');
    }
    expect(reached).toEqual(candidate.evidence.map((_, index) => index));
    expect(Math.max(...sizes)).toBeLessThanOrEqual(2500);
    await page.getByRole('button', { name: 'Raw candidate', exact: true }).click();
    expect(JSON.parse(await page.getByLabel('Retained candidate JSON').innerText())).toEqual(candidate);
    await census(2500);
    await page.keyboard.press('Escape');
    await testInfo.attach('all-evidence-navigation', { body: JSON.stringify({ reached, sizes }), contentType: 'application/json' });
    expect(writes).toEqual([]); expect(errors).toEqual([]);
  });
}

test('ordinary Back and Forward restore candidate selection, overview focus and scroll', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await installApiFixture(page);
  await page.route(`**/api/v1/candidates/${encodedId}`, route => route.fulfill({ json: candidate }));
  await page.goto('/login');
  await page.getByLabel('Username').fill('analyst');
  await page.getByRole('button', { name: 'Development login' }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
  await page.goto(`/candidates/${encodedId}?q=context&page=4`);
  const opener = page.getByRole('button', { name: '근거 1 · 주기적 비콘', exact: true });
  await expect(opener).toBeVisible();
  await page.mouse.wheel(0, 150);
  await expect.poll(() => page.evaluate(() => scrollY)).toBe(150);
  await opener.focus();
  const before = await page.evaluate(() => scrollY);
  await opener.click();
  await expect(page.locator('.evidence.detailed')).toBeVisible();
  await page.goBack();
  await expect(opener).toBeFocused();
  await expect.poll(() => page.evaluate(() => scrollY)).toBe(before);
  await page.goForward();
  await expect(page.locator('.evidence.detailed')).toBeVisible();
  await expect(page).toHaveURL(/detail=evidence&evidence=0/);
  await page.getByRole('button', { name: 'Network context', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Network context', exact: true })).toBeVisible();
  await page.goBack();
  await expect(page.locator('.evidence.detailed')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page).toHaveURL(/\?q=context&page=4$/);
  await expect(opener).toBeFocused();
});

test('a delayed deep-link read never steals an interaction already made in the shell', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 900 });
  await installApiFixture(page);
  let release!: () => void;
  const delayed = new Promise<void>(resolve => { release = resolve; });
  await page.route(`**/api/v1/candidates/${encodedId}`, async route => { await delayed; await route.fulfill({ json: candidate }); });
  await page.goto('/login');
  await page.getByLabel('Username').fill('analyst');
  await page.getByRole('button', { name: 'Development login' }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
  await page.goto(`/candidates/${encodedId}?detail=evidence&evidence=29`);
  const menu = page.getByRole('button', { name: '메뉴 / Menu' });
  await menu.click();
  release();
  await expect(page.getByRole('region', { name: 'Candidate result summary' })).toBeVisible();
  await expect(menu).toBeFocused();
  await expect(page.getByRole('dialog', { name: 'Selected candidate detail' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Open requested detail' }).click();
  await expect(page.locator('.evidence.detailed')).toContainText('Retained reason 30');
});


test('ordinary flow history preserves requested pages and an uncertain label across close', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await installApiFixture(page);
  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  const writes: { path: string; body: unknown }[] = []; const reads: string[] = [];
  await page.route('**/api/v1/**', async route => {
    const url = new URL(route.request().url()); const path = url.pathname.replace('/api/v1', '');
    if (path === `/candidates/${encodedId}`) return route.fulfill({ json: candidate });
    if (path === '/analysis-jobs/job-1/flows') {
      reads.push(url.search); const number = url.searchParams.get('page') === '2' ? 2 : 1;
      return route.fulfill({ json: { page: number, page_size: 1, total: 2, items: [{ flow_id: number === 2 ? 'flow-b' : 'flow-a', job_id: 'job-1', timestamp: candidate.first_seen, source_ip: '10.0.0.5', destination_ip: candidate.candidate_ip, protocol: 'TCP', direction: 'OUTBOUND', has_payload: true }] } });
    }
    if (path === '/analysis-jobs/job-1/flow-labels') { writes.push({ path, body: route.request().postDataJSON() }); await pending; return route.fulfill({ status: 503, json: { error: { message: 'Uncertain label outcome' } } }); }
    return route.fallback();
  });
  await page.goto('/login');
  await page.getByLabel('Username').fill('analyst');
  await page.getByRole('button', { name: 'Development login' }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
  await page.goto(`/candidates/${encodedId}?q=context&detail=flows&flow_page=2&flow=flow-b`);
  await page.getByRole('button', { name: 'Mark benign flow-b' }).click();
  expect(writes).toEqual([]); expect(reads).toHaveLength(1); expect(reads[0]).toContain('&page=2&page_size=50');
  await page.getByLabel('Analyst note').fill('Keep this browser draft');
  await page.getByRole('button', { name: 'Save BENIGN label' }).click();
  await page.getByRole('button', { name: 'Previous flows' }).click();
  await page.getByRole('button', { name: 'Inspect flow flow-a' }).click();
  await expect(page).toHaveURL(/flow_page=1&detail=flows&flow=flow-a/);
  await page.goBack(); await page.goBack();
  await expect(page.getByLabel('Analyst note')).toHaveValue('Keep this browser draft');
  await expect(page.getByRole('button', { name: 'Saving…', exact: true })).toBeDisabled();
  await page.keyboard.press('Escape');
  await expect(page).toHaveURL(/\?q=context&flow_page=2$/);
  await expect(page.getByText('flow-b · Saving…')).toBeVisible();
  release();
  await expect(page.getByText('Uncertain label outcome')).toBeVisible();
  await page.getByRole('button', { name: 'Flow review', exact: true }).click();
  await page.getByRole('button', { name: 'Inspect flow flow-b' }).click();
  await expect(page.getByLabel('Analyst note')).toHaveValue('Keep this browser draft');
  expect(writes).toEqual([{ path: '/analysis-jobs/job-1/flow-labels', body: { flow_id: 'flow-b', verdict: 'BENIGN', confidence: 'HIGH', note: 'Keep this browser draft', create_signature: false, signature_description: '' } }]);
});


test('Escape retires candidate modality synchronously while the URL transition is scheduled', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 900 });
  await installApiFixture(page);
  await page.route(`**/api/v1/candidates/${encodedId}`, route => route.fulfill({ json: candidate }));
  await page.goto('/login');
  await page.getByLabel('Username').fill('analyst');
  await page.getByRole('button', { name: 'Development login' }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
  await page.goto(`/candidates/${encodedId}`);
  await page.getByRole('button', { name: 'Network context', exact: true }).click();
  await expect(page.getByRole('dialog', { name: 'Selected candidate detail' })).toBeVisible();
  const immediate = await page.evaluate(() => {
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    return { inert: document.querySelectorAll('[inert]').length, dialogs: document.querySelectorAll('[role="dialog"]').length };
  });
  expect(immediate).toEqual({ inert: 0, dialogs: 0 });
  await expect(page).toHaveURL(`/candidates/${encodedId}`);
});

for (const width of [1280, 390]) {
  for (const result of ['valid', 'missing', 'wrong-page', 'wrong-job', 'evidence'] as const) {
    test(`deferred full intent ${result} at ${width}px`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: 900 });
      await installApiFixture(page);
      let release!: () => void;
      const pending = new Promise<void>(resolve => { release = resolve; });
      const reads: string[] = []; const writes: string[] = []; const errors: string[] = [];
      page.on('pageerror', error => errors.push(error.message));
      await page.route('**/api/v1/**', async route => {
        const url = new URL(route.request().url()); const path = url.pathname.replace('/api/v1', '');
        if (route.request().method() !== 'GET' && path !== '/auth/dev-login') writes.push(path);
        if (path === `/candidates/${encodedId}`) { await pending; return route.fulfill({ json: candidate }); }
        if (path === '/analysis-jobs/job-1/flows') {
          reads.push(url.search);
          return route.fulfill({ json: { page: result === 'wrong-page' ? 1 : 2, page_size: 50, total: 51, items: [{ flow_id: result === 'missing' ? 'other-flow' : 'flow-b', job_id: result === 'wrong-job' ? 'other-job' : 'job-1', timestamp: candidate.first_seen, source_ip: '10.0.0.5', destination_ip: candidate.candidate_ip, protocol: 'TCP', direction: 'OUTBOUND', has_payload: true }] } });
        }
        return route.fallback();
      });
      await page.goto('/login');
      await page.getByLabel('Username').fill('analyst');
      await page.getByRole('button', { name: 'Development login' }).click();
      await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
      const search = `?q=keep&page=4&${result === 'evidence' ? 'detail=evidence&evidence=29' : 'detail=flows&flow_page=2&flow=flow-b'}#context`;
      await page.goto(`/candidates/${encodedId}${search}`);
      await expect(page.getByText('Candidate identifier', { exact: true })).toBeVisible();
      const shellControl = width === 390 ? page.getByRole('button', { name: '메뉴 / Menu' }) : page.locator('#shell-navigation a').first();
      if (width === 390) await shellControl.click();
      else { await shellControl.focus(); await page.keyboard.press('Shift'); }
      release();
      await expect(page.getByRole('region', { name: 'Candidate result summary' })).toBeVisible();
      await expect(shellControl).toBeFocused();
      await expect(page.getByRole('heading', { name: 'Selected candidate detail', exact: true })).toHaveCount(0);
      expect(reads).toEqual([]); expect(writes).toEqual([]);
      const initialDOM = await page.evaluate(() => document.querySelectorAll('*').length);
      expect(initialDOM).toBeLessThanOrEqual(1200);
      await page.getByRole('button', { name: 'Open requested detail' }).click();
      await expect(page).toHaveURL(`/candidates/${encodedId}${search}`);
      if (result === 'evidence') {
        await expect(page.locator('.evidence.detailed')).toContainText('Retained reason 30');
        expect(reads).toEqual([]);
      } else {
        if (result === 'valid') await expect(page.getByRole('button', { name: 'Mark benign flow-b' })).toBeEnabled();
        else {
          await expect(page.getByText('Selected flow is not available on this source page. Select a retained flow explicitly.')).toBeVisible();
          await expect(page.getByRole('button', { name: 'Mark benign flow-b' })).toHaveCount(0);
        }
        expect(reads).toEqual([`?candidate_ip=${encodeURIComponent(candidate.candidate_ip)}&page=2&page_size=50`]);
      }
      const expandedDOM = await page.evaluate(() => document.querySelectorAll('*').length);
      expect(expandedDOM).toBeLessThanOrEqual(2500);
      await testInfo.attach('deferred-intent', { body: JSON.stringify({ result, width, initialDOM, expandedDOM, reads, writes }), contentType: 'application/json' });
      expect(writes).toEqual([]); expect(errors).toEqual([]);
    });
  }
}
