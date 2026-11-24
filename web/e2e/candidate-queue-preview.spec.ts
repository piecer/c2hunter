import { withLegacyAuthentication } from './auth-fixture';
import { expect, test, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

const rows = Array.from({ length: 101 }, (_, i) => ({
  id: i === 0 ? 'opaque /?#% ' + 'identifier'.repeat(30) : `queue-${i}`,
  job_id: 'queue-job', candidate_ip: `2001:db8:1234:5678:abcd:1234:5678:${i + 1}`,
  score: 80, severity: 'HIGH', workflow_status: 'NEEDS_REVIEW', candidate_kind: 'COMMUNICATION_STATUS', occurrence_count: 3, duplicate_count: 2,
  ti_assessment: { status: 'PARTIAL', signal: 'INCOMPLETE', successful_providers: 2, configured_providers: 3, positive_providers: 2, misp_event_count: 1, virustotal_malicious: 8, virustotal_suspicious: 2, abuse_confidence_score: 91 },
  hosts: ['10.0.0.5'], sensors: ['sensor-a'], protocols: ['TCP'], ports: [443],
  first_seen: '2026-11-15T00:00:00Z', last_seen: '2026-11-15T00:01:00Z',
  evidence: Array.from({ length: 30 }, (_, n) => ({ type: 'BEACON', description: `Reason ${i}-${n}`, metrics: { values: Array(100).fill(1) } })),
}));
async function fixture(page: Page) {
  const reads: string[] = []; const writes: string[] = [];
  await page.addInitScript(() => localStorage.setItem('c2hunter-token', 'queue-fixture'));
  await page.route('**/api/v1/**', withLegacyAuthentication(async route => {
    const url = new URL(route.request().url()); const path = url.pathname.replace('/api/v1', '');
    if (route.request().method() !== 'GET') writes.push(path); else reads.push(path + url.search);
    if (path === '/analysis-jobs/queue-job') return route.fulfill({ json: { id: 'queue-job', name: 'Queue investigation', status: 'COMPLETED', analysis: { module: 'c2' }, candidate_count: rows.length, warnings: ['Limited observation coverage.'] } });
    if (path === '/candidates' || path === '/analysis-jobs/queue-job/candidates') {
      const current = Number(url.searchParams.get('page') ?? 1); const size = Number(url.searchParams.get('page_size'));
      return route.fulfill({ json: { items: rows.slice((current - 1) * size, current * size), page: current, page_size: size, total: rows.length, workflow_counts: { needs_review: 101, in_review: 0, action_required: 0, action_in_progress: 0, action_completed: 0, false_positive: 0, done: 0 } } });
    }
    const row = rows.find(row => path === `/candidates/${encodeURIComponent(row.id)}` || path === `/analysis-jobs/queue-job/candidates/${encodeURIComponent(row.id)}`);
    return route.fulfill({ json: row ?? { items: [], total: 0 } });
  }));
  return { reads, writes };
}
async function geometry(page: Page) {
  return page.evaluate(() => ({ nodes: document.querySelectorAll('*').length, document: document.documentElement.scrollWidth, body: document.body.scrollWidth, width: innerWidth }));
}

for (const scope of ['global', 'job']) for (const width of [1280, 390]) for (const language of scope === 'job' ? ['ko', 'en'] : ['en']) {
  test(`${scope} queue preview at ${width}px ${language}: bounded, readonly, every page and keyboard return`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    await page.addInitScript(value => localStorage.setItem('c2hunter-report-language', value), language);
    const { reads, writes } = await fixture(page);
    const errors: string[] = []; page.on('pageerror', error => errors.push(error.message));
    const path = scope === 'job' ? '/analyses/queue-job' : '/candidates';
    await page.goto(path);
    const table = page.getByRole('table', { name: scope === 'job' ? 'Analysis candidates' : 'C2 candidates', exact: true });
    await expect(table).toBeVisible();
    await expect(table.locator('tbody tr')).toHaveCount(scope === 'job' ? 25 : 50);
    expect(reads.length).toBe(scope === 'job' ? 2 : 1);
    const initial = await geometry(page);
    expect(initial.nodes).toBeLessThanOrEqual(1200);
    expect(initial.document).toBeLessThanOrEqual(width); expect(initial.body).toBeLessThanOrEqual(width);
    const ko = scope === 'job' && language === 'ko';
    const previewName = (i: number) => `${ko ? '후보 미리보기' : 'Preview candidate'} ${rows[i].candidate_ip}`;
    const closeName = ko ? '후보 상세 닫기' : 'Close candidate detail';
    const title = ko ? '선택한 후보 상세' : 'Selected candidate detail';
    const panel = page.getByRole(width < 1200 ? 'dialog' : 'region', { name: title, exact: true });
    let peak = initial.nodes;
    // A/B/A with both server destinations previously visited; never accumulate details.
    for (const i of [0, 1, 0, 1, 0]) {
      const trigger = page.getByRole('button', { name: previewName(i), exact: true });
      await trigger.click();
      await expect(panel.getByRole('heading', { name: rows[i].candidate_ip, exact: true })).toBeVisible();
      await expect(page.locator('[data-candidate-preview]')).toHaveCount(1);
      await expect(panel.getByRole('listitem')).toHaveCount(3);
      await expect(panel.getByRole('heading', { name: title })).toBeFocused();
      await expect(panel.getByRole('link', { name: ko ? '전체 조사 열기' : 'Open full investigation' })).toHaveAttribute('href', `/candidates/${encodeURIComponent(rows[i].id)}`);
      const g = await geometry(page); peak = Math.max(peak, g.nodes);
      expect(g.nodes).toBeLessThanOrEqual(2500); expect(g.document).toBeLessThanOrEqual(width); expect(g.body).toBeLessThanOrEqual(width);
      if (i === 0) await expect(panel.getByText(rows[i].id, { exact: true })).toBeVisible();
      if (width < 1200) {
        await page.keyboard.press('Tab'); await expect(panel.getByRole('button', { name: closeName })).toBeFocused();
        await page.keyboard.press('Shift+Tab'); await expect(panel.getByRole('link')).toBeFocused();
        await page.keyboard.press('Tab'); await expect(panel.getByRole('button', { name: closeName })).toBeFocused();
        await expect(panel).toHaveAttribute('aria-modal', 'true');
      } else {
        if (scope === 'global') {
          // Local table scrolling is preferable to one-character-wide columns.
          const score = await table.locator('thead th').nth(2).boundingBox();
          expect(score!.width).toBeGreaterThanOrEqual(50);
          const previewBox = await trigger.boundingBox();
          expect(previewBox!.width).toBeGreaterThanOrEqual(80);
        }
        await expect(panel).not.toHaveAttribute('aria-modal');
        const listBox = await table.boundingBox(); const detailBox = await panel.boundingBox();
        expect(detailBox!.x).toBeGreaterThan(listBox!.x);
      }
      if (i === 0) await page.screenshot({ path: testInfo.outputPath('queue-preview.png') });
      await page.keyboard.press('Escape');
      await expect(panel).toHaveCount(0); await expect(trigger).toBeFocused();
      await expect(page).toHaveURL(new RegExp(path + '$'));
    }
    const visited: string[] = [];
    const size = scope === 'job' ? 25 : 50;
    for (let current = 1; current <= Math.ceil(rows.length / size); current++) {
      await expect(table.getByRole('link', { name: rows[(current - 1) * size].candidate_ip, exact: true })).toBeVisible();
      visited.push(...await table.locator('tbody a').allTextContents());
      const next = page.getByRole('button', { name: ko ? '다음 후보' : 'Next candidates', exact: true });
      if (current < Math.ceil(rows.length / size)) await next.click(); else await expect(next).toBeDisabled();
    }
    expect(visited).toEqual(rows.map(row => row.candidate_ip));
    expect(writes).toEqual([]); expect(errors).toEqual([]);
    await testInfo.attach('queue-budget', { body: JSON.stringify({ initial, peak, reached: visited.length }), contentType: 'application/json' });
    await page.screenshot({ path: testInfo.outputPath('queue-final-page.png'), fullPage: true });
  });
}

test('global queue real Back/Forward restores A/B/A selection, focus, scroll and filters', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  const { writes } = await fixture(page);
  await page.goto('/candidates?page=2&severity=HIGH&sort=-score&context=keep');
  const a = page.getByRole('button', { name: `Preview candidate ${rows[75].candidate_ip}`, exact: true });
  const b = page.getByRole('button', { name: `Preview candidate ${rows[76].candidate_ip}`, exact: true });
  await a.scrollIntoViewIfNeeded(); await a.focus(); const listTop = await page.evaluate(() => scrollY);
  await a.click(); await expect(page.getByText('Reason 75-0', { exact: true })).toBeVisible();
  await b.scrollIntoViewIfNeeded(); await b.focus(); const aTop = await page.evaluate(() => scrollY);
  await b.click(); await expect(page.getByText('Reason 76-0', { exact: true })).toBeVisible();
  await b.click(); // same-id no-op
  await page.goBack(); await expect(page.getByText('Reason 75-0', { exact: true })).toBeVisible();
  await expect(b).toBeFocused(); await expect.poll(() => page.evaluate(() => scrollY)).toBe(aTop);
  await page.goBack(); await expect(page.locator('[data-candidate-preview]')).toHaveCount(0);
  await expect(a).toBeFocused(); await expect.poll(() => page.evaluate(() => scrollY)).toBe(listTop);
  await page.goForward(); await expect(page.getByText('Reason 75-0', { exact: true })).toBeVisible();
  await page.goForward(); await expect(page.getByText('Reason 76-0', { exact: true })).toBeVisible();
  await expect(page.getByRole('combobox', { name: 'Severity', exact: true })).toHaveValue('HIGH');
  expect(new URL(page.url()).searchParams.get('context')).toBe('keep');
  expect(writes).toEqual([]);
});


test('narrow Back retires modal inertness before returning keyboard focus to the list', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 900 });
  await fixture(page);
  await page.goto('/candidates');
  const trigger = page.getByRole('button', { name: `Preview candidate ${rows[1].candidate_ip}`, exact: true });
  await trigger.click();
  await expect(page.getByRole('dialog').getByText('Reason 1-0', { exact: true })).toBeVisible();
  await page.goBack();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect(trigger).toBeFocused();
  await page.goForward();
  await expect(page.getByRole('dialog').getByText('Reason 1-0', { exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Selected candidate detail' })).toBeFocused();
});


test('deep-link failure and retry remain inside the active narrow modal; missing source close preserves context', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 900 });
  await fixture(page);
  let status = 503;
  await page.route('**/api/v1/candidates/queue-1', route => status === 200 ? route.fulfill({ json: rows[1] }) : route.fulfill({ status, json: { error: { code: status === 404 ? 'CANDIDATE_NOT_FOUND' : 'TEMPORARY_FAILURE' } } }));
  await page.goto('/candidates?severity=HIGH&context=keep&candidate=queue-1');
  const dialog = page.getByRole('dialog', { name: 'Selected candidate detail' });
  await expect(dialog.getByRole('alert')).toContainText('could not be refreshed');
  await expect(dialog.getByRole('button', { name: 'Retry candidate preview' })).toBeVisible();
  status = 200;
  await dialog.getByRole('button', { name: 'Retry candidate preview' }).click();
  await expect(dialog.getByText('Reason 1-0', { exact: true })).toBeVisible();
  // Reload an already visited selection after authoritative retirement.
  await page.keyboard.press('Escape');
  status = 404;
  await page.getByRole('button', { name: `Preview candidate ${rows[1].candidate_ip}`, exact: true }).click();
  await expect(dialog.getByRole('alert')).toContainText('unavailable in this scope');
  await expect(dialog.getByText('Reason 1-0', { exact: true })).toHaveCount(0);
  await expect(dialog.getByRole('link', { name: 'Open full investigation' })).toHaveCount(0);
  await page.keyboard.press('Escape');
  await expect(page).toHaveURL(/\/candidates\?severity=HIGH&context=keep$/);
});


for (const scope of ['global', 'job']) for (const width of [1280, 390]) for (const delayed of [false, true]) {
  test(`${scope} full investigation roundtrip at ${width}px with ${delayed ? 'delayed' : 'cached'} list`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    if (delayed) await page.clock.install();
    await page.addInitScript(() => localStorage.setItem('c2hunter-report-language', 'en'));
    await fixture(page);
    const path = scope === 'global' ? '/candidates?page=2&severity=HIGH&sort=-score&context=keep' : '/analyses/queue-job?candidate_page=2&context=keep';
    const index = scope === 'global' ? 75 : 40;
    await page.goto(path);
    const trigger = page.getByRole('button', { name: `Preview candidate ${rows[index].candidate_ip}`, exact: true });
    await trigger.scrollIntoViewIfNeeded(); await trigger.click();
    const panel = page.getByRole(width < 1200 ? 'dialog' : 'region', { name: 'Selected candidate detail', exact: true });
    const link = panel.getByRole('link', { name: 'Open full investigation' });
    await expect(link).toBeVisible(); await link.scrollIntoViewIfNeeded();
    const selectedUrl = page.url(); const selectedScroll = await page.evaluate(() => scrollY);
    await link.click();
    await expect(page).toHaveURL(new RegExp(`/candidates/queue-${index}$`));
    await expect(page.locator('[data-candidate-preview]')).toHaveCount(0);
    let release!: () => void;
    const pending = new Promise<void>(resolve => { release = resolve; });
    let listStarted = false;
    let listFinished = false;
    if (delayed) {
      await page.clock.fastForward(11_000); // Expire the real 10s list cache, not a test-only query client.
      await page.route(scope === 'global' ? '**/api/v1/candidates?*' : '**/api/v1/analysis-jobs/queue-job/candidates?*', async route => {
        listStarted = true; await pending;
        const size = scope === 'global' ? 50 : 25;
        await route.fulfill({ json: { items: rows.slice(size, size * 2).map(row => ({ ...row, score: row.score + 1 })), page: 2, page_size: size, total: rows.length } });
        listFinished = true;
      });
    }
    await page.goBack();
    await expect(page).toHaveURL(selectedUrl);
    await expect(panel.getByText(`Reason ${index}-0`, { exact: true })).toBeVisible();
    await expect.poll(() => page.evaluate(() => scrollY)).toBe(selectedScroll);
    if (delayed) {
      await expect.poll(() => listStarted).toBe(true);
      expect(listFinished).toBe(false);
      await link.focus(); // A fresh list must not steal the user's new focus.
    }
    release();
    if (delayed) {
      await expect.poll(() => listFinished).toBe(true);
      const table = page.getByRole('table', { name: scope === 'global' ? 'C2 candidates' : 'Analysis candidates', exact: true, includeHidden: true });
      await expect(table.locator('tbody tr').first()).toContainText('81');
      await expect(link).toBeFocused();
    }
    await expect(trigger).toHaveAttribute('aria-expanded', 'true');
    await panel.getByRole('button', { name: 'Close candidate detail' }).click();
    await expect(panel).toHaveCount(0); await expect(trigger).toBeFocused();
    await expect(page).toHaveURL(new URL(path, page.url()).href);
    await testInfo.attach('roundtrip', { body: JSON.stringify({ scope, width, delayed, selectedUrl, selectedScroll }), contentType: 'application/json' });
  });
}

for (const scope of ['global', 'job']) for (const language of ['en', 'ko']) {
  test(`${scope} actual producer warnings inside 390px modal (${language})`, async ({ page }, testInfo) => {
    const python = process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python');
    const wire = execFileSync(python, [resolve('tests/candidate_queue_warning_fixture.py')], { encoding: 'utf8', timeout: 30000 });
    const { candidate } = JSON.parse(wire);
    await page.setViewportSize({ width: 390, height: 900 });
    await page.addInitScript(value => localStorage.setItem('c2hunter-report-language', value), language);
    await fixture(page);
    // The list stays at its maximum page size; only the selected detail uses real producer bytes.
    await page.route('**/api/v1/**/queue-warning-candidate', route => route.fulfill({ json: candidate }));
    const path = scope === 'global' ? '/candidates?candidate=queue-warning-candidate' : '/analyses/queue-job?candidate=queue-warning-candidate';
    await page.goto(path);
    const ko = scope === 'job' && language === 'ko';
    const panel = page.getByRole('dialog', { name: ko ? '선택한 후보 상세' : 'Selected candidate detail' });
    const limitations = panel.getByRole('region', { name: ko ? '근거 관측 한계' : 'Evidence limitations' });
    await expect(limitations).toBeVisible();
    for (const text of ko ? ['응답 미관측은 호스트 사용 불가', '캡처 손실이나 비대칭 관측', '응답 상관 분석의 보존 한도'] : ['No response does not establish', 'Capture loss or asymmetric visibility', 'Response correlation reached its retention limit']) await expect(limitations.getByText(text, { exact: false })).toBeVisible();
    await limitations.getByRole('button', { name: ko ? '모든 근거 경고 보기' : 'Show all evidence warnings' }).click();
    const codes = candidate.evidence.flatMap((item: { warnings: string[] }) => item.warnings);
    await expect(limitations.locator('li code')).toHaveText(codes);
    for (const code of ['no_response_is_not_host_unavailable', 'capture_loss_or_asymmetry_possible', 'response_correlation_truncated']) await expect(limitations.getByText(code, { exact: true })).toBeVisible();
    const measured = await geometry(page);
    expect(measured.nodes).toBeLessThanOrEqual(2500);
    expect(measured.document).toBeLessThanOrEqual(390); expect(measured.body).toBeLessThanOrEqual(390);
    await testInfo.attach('producer-warning-wire', { body: wire, contentType: 'application/json' });
    await testInfo.attach('warning-budget', { body: JSON.stringify(measured), contentType: 'application/json' });
    await page.screenshot({ path: testInfo.outputPath('source-warnings.png'), fullPage: true });
    await limitations.getByRole('button', { name: ko ? '근거 경고 숨기기' : 'Hide evidence warnings' }).click();
    await expect(limitations.locator('li')).toHaveCount(0);
    await page.keyboard.press('Escape');
    await expect(panel).toHaveCount(0);
    await expect(page.getByRole('heading', { name: scope === 'global' ? 'Candidates' : ko ? '탐지 후보' : 'Detected candidates', exact: true })).toBeFocused();
  });
}


for (const scope of ['global', 'job']) for (const width of [1280, 390]) {
  test(`${scope} missing row after full investigation return at ${width}px uses heading fallback`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.clock.install();
    await page.addInitScript(() => localStorage.setItem('c2hunter-report-language', 'en'));
    await fixture(page);
    const path = scope === 'global' ? '/candidates?severity=HIGH&context=keep' : '/analyses/queue-job?context=keep';
    await page.goto(path);
    await page.getByRole('button', { name: `Preview candidate ${rows[1].candidate_ip}`, exact: true }).click();
    const panel = page.getByRole(width < 1200 ? 'dialog' : 'region', { name: 'Selected candidate detail', exact: true });
    await panel.getByRole('link', { name: 'Open full investigation' }).click();
    await expect(page).toHaveURL(/\/candidates\/queue-1$/);
    await page.clock.fastForward(11_000);
    await page.route(scope === 'global' ? '**/api/v1/candidates?*' : '**/api/v1/analysis-jobs/queue-job/candidates?*', route => route.fulfill({ json: { items: [rows[0]], page: 1, page_size: scope === 'global' ? 50 : 25, total: 1 } }));
    await page.goBack();
    await expect(panel.getByText('Reason 1-0', { exact: true })).toBeVisible();
    await expect(page.locator('button[aria-controls="candidate-selected-detail"][aria-expanded="true"]')).toHaveCount(0);
    // Absence from a list does not declare the retained scoped detail unavailable.
    await expect(panel.getByRole('link', { name: 'Open full investigation' })).toBeVisible();
    await panel.getByRole('button', { name: 'Close candidate detail' }).click();
    await expect(page.getByRole('heading', { name: scope === 'global' ? 'Candidates' : 'Detected candidates', exact: true })).toBeFocused();
    await expect(page).toHaveURL(new URL(path, page.url()).href);
  });
}
