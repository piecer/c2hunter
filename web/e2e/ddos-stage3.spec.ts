import { test, expect, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { readFileSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';

// Actual producer bytes and persisted SQLite fixture; only browser HTTP is mocked.
const root = process.env.C2HUNTER_DDOS_FIXTURE ?? mkdtempSync(join(tmpdir(), 'ddos-browser-'));
if (!process.env.C2HUNTER_DDOS_FIXTURE) execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python'), ['tests/ddos_stage3_fixture.py', root]);
const fixture = JSON.parse(readFileSync(join(root, 'browser-fixture.json'), 'utf8'));
const normal = fixture.jobs.normal;
async function install(page: Page, language: string) {
  const errors: string[] = [], writes: { path: string; body: unknown }[] = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.addInitScript(lang => { localStorage.setItem('c2hunter-token', 'owned-browser-fixture'); localStorage.setItem('c2hunter-report-language', lang); }, language);
  await page.route('**/api/v1/**', async route => {
    const req = route.request(), url = new URL(req.url()), path = url.pathname.replace('/api/v1', '');
    let body: unknown = { items: [] };
    if (req.method() !== 'GET') {
      writes.push({ path, body: req.postDataJSON() });
      return route.fulfill({ status: 422, contentType: 'application/json', body: JSON.stringify({ error: { code: 'DDOS_REFERENCE_RECORD_LIMIT', message: 'Server eligibility rejection (browser transport fixture)' } }) });
    }
    if (path === '/sensors') body = { items: [{ sensor_id: 'owned-offline-sensor', name: 'Owned offline sensor', status: 'ONLINE' }] };
    else if (path === '/analysis-jobs') {
      const pageNumber = Number(url.searchParams.get('page') ?? 1);
      const entries = pageNumber === 1 ? Array.from({ length: 20 }, (_, i) => ({ ...normal, id: `listed-${i}-` + 'x'.repeat(180), dataset_id: `dataset-${i}-` + 'y'.repeat(180) })) : [normal];
      body = { items: entries, total: 21, page: pageNumber, page_size: 20 };
    } else if (path.startsWith('/analysis-jobs/') && !path.endsWith('/ai-runs')) {
      const id = path.split('/')[2];
      body = Object.values(fixture.jobs).find((job: unknown) => (job as { id: string }).id === id) ?? { ...fixture.jobs.unmeasured, id, ddos_attack: fixture.reports[id] };
    } else if (path === '/ai-capabilities') body = { available: false, ddos_interpretation: false, reason: 'No model calls in fixture' };
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify(body) });
  });
  return { errors, writes };
}
const geometry = (page: Page) => page.evaluate(() => ({ width: innerWidth, body: document.body.scrollWidth, document: document.documentElement.scrollWidth, nodes: document.querySelectorAll('*').length }));
for (const width of [1280, 390]) for (const language of ['ko', 'en']) {
  test(`DDoS producer view ${width} ${language}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 });
    const { errors, writes } = await install(page, language);
    await page.goto(`/analyses/${fixture.jobs.measured.id}`);
    const glance = page.getByRole('region', { name: language === 'en' ? 'DDoS at a glance' : 'DDoS 한눈에 보기' });
    await expect(glance).toBeVisible(); await glance.scrollIntoViewIfNeeded();
    const initial = await geometry(page); expect(initial.document).toBeLessThanOrEqual(width); expect(initial.body).toBeLessThanOrEqual(width); expect(initial.nodes).toBeLessThan(900);
    await page.screenshot({ path: info.outputPath('overview.png') });
    const toggle = page.getByRole('button', { name: /Show detailed evidence|Hide detailed evidence|상세 근거 보기|상세 근거 숨기기/ }).first();
    await toggle.focus(); await page.keyboard.press('Enter');
    const inspect = page.getByRole('button', { name: /Inspect candidate|후보 검토/ }).first();
    await inspect.focus(); await page.keyboard.press('Enter');
    const detail = page.getByRole('region', { name: language === 'en' ? 'Candidate inspection' : '후보 검토 상세' });
    await expect(detail).toContainText('VERIFY_TARGET_OWNERSHIP'); await expect(detail).toContainText(normal.dataset_id);
    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: /Download reviewed candidate JSON|검토용 후보 JSON 다운로드/ }).click();
    const download = await downloadPromise; const path = info.outputPath(download.suggestedFilename()); await download.saveAs(path);
    const bytes = readFileSync(path); expect(bytes.length).toBeLessThanOrEqual(65536);
    const exported = JSON.parse(bytes.toString('utf8')); expect(exported.job_id).toBe(fixture.jobs.measured.id);
    expect(exported.evaluation).toEqual(fixture.jobs.measured.ddos_attack.findings[0].signature_candidates[0].evaluation);
    expect(exported.packet_selection.status).toBe('EXACT_OFFLINE'); expect(exported.packet_selection.capture_sha256).toBe(fixture.jobs.measured.source.sha256);
    expect(download.suggestedFilename()).toMatch(/^ddos-sig-[a-f0-9]{16}-review-v1.json$/);
    const filterPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: /Download passive BPF v1|수동 BPF v1 다운로드/ }).click();
    const filterDownload = await filterPromise; const filterPath = info.outputPath(filterDownload.suggestedFilename()); await filterDownload.saveAs(filterPath);
    expect(filterDownload.suggestedFilename()).toMatch(/^ddos-sig-[a-f0-9]{16}-passive-v1\.bpf$/);
    const native = execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python'), ['tests/ddos_native_filter.py', join(root, 'measured.pcap'), path, filterPath], { encoding: 'utf8' });
    await info.attach('download-native-proof', { body: native, contentType: 'application/json' });

    const expanded = await geometry(page); expect(expanded.document).toBeLessThanOrEqual(width); expect(expanded.nodes).toBeLessThan(900);
    await detail.screenshot({ path: info.outputPath('candidate.png') });
    await inspect.focus(); await page.keyboard.press('Enter'); await expect(inspect).toBeFocused(); await expect(detail).toHaveCount(0);
    await toggle.focus(); await page.keyboard.press('Enter'); await expect(toggle).toBeFocused();
    expect((await geometry(page)).nodes).toBe(initial.nodes);
    expect(errors).toEqual([]); expect(writes).toEqual([]);
    await info.attach('geometry', { body: JSON.stringify({ initial, expanded, collapsed: await geometry(page) }), contentType: 'application/json' });
    await info.attach('accessibility', { body: await page.locator('main').ariaSnapshot(), contentType: 'text/plain' });
    const cdp = await page.context().newCDPSession(page);
    const ax = await cdp.send('Accessibility.getFullAXTree');
    expect(ax.nodes.some(node => node.role?.value === 'button' && /Show detailed evidence|상세 근거 보기/.test(String(node.name?.value)) && node.properties?.some(property => property.name === 'focused' && property.value.value === true))).toBe(true);
    await info.attach('chromium-accessibility-tree', { body: JSON.stringify(ax), contentType: 'application/json' });
    await cdp.detach();
  });
}

for (const width of [1280, 390]) for (const language of ['ko', 'en']) test(`real producer scenarios ${width} ${language} retain every finding with bounded single-owner DOM`, async ({ page }, info) => {
  await page.setViewportSize({ width, height: 900 });
  await install(page, language);
  const observations = [];
  for (const name of Object.keys(fixture.reports)) {
    await page.goto('/analyses/' + name);
    await expect(page.getByRole('region', { name: language === 'en' ? 'DDoS at a glance' : 'DDoS 한눈에 보기' })).toBeVisible();
    await expect(page.getByText('Unsupported DDoS report. Review coverage and update the client.')).toHaveCount(0);
    if (name === 'qualified_coverage') {
      const glance = page.getByRole('region', { name: language === 'en' ? 'DDoS at a glance' : 'DDoS 한눈에 보기' });
      for (const phrase of language === 'en' ? ['packet drops', 'clock skew', 'parser skipped', 'lower bounds'] : ['패킷 drop', '시계 오차', '파서가', '하한']) await expect(glance).toContainText(phrase);
    }
    const report = fixture.reports[name]; let reached = 0, peak = 0;
    do {
      const toggles = page.getByRole('button', { name: /Show detailed evidence|Hide detailed evidence|상세 근거 보기|상세 근거 숨기기/ });
      for (let i = 0; i < await toggles.count(); i++) {
        await toggles.nth(i).click();
        await expect(page.getByRole('region', { name: language === 'en' ? 'DDoS finding evidence' : 'DDoS 발견 근거' })).toHaveCount(1);
        const candidates = page.getByRole('button', { name: /Inspect candidate|후보 검토/ });
        for (let c = 0; c < await candidates.count(); c++) {
          await candidates.nth(c).click();
          await expect(page.getByRole('region', { name: language === 'en' ? 'Candidate inspection' : '후보 검토 상세' })).toHaveCount(1);
          const bounds = await geometry(page);
          expect(bounds.document).toBeLessThanOrEqual(width);
          peak = Math.max(peak, bounds.nodes);
          if (name === 'maximum' && reached === 0 && c === 0) {
            const action = page.getByLabel(language === 'en' ? 'Normal reference action' : '정상 참조 작업');
            await action.selectOption('select'); await expect(page.getByRole('radio')).toHaveCount(20);
            const combined = await geometry(page); expect(combined.document).toBeLessThanOrEqual(width);
            peak = Math.max(peak, combined.nodes); await action.selectOption('clear');
          }
        }
        await toggles.nth(i).click(); reached++;
      }
      const next = page.getByRole('navigation', { name: language === 'en' ? 'DDoS finding pages' : 'DDoS 발견 항목 페이지' }).getByRole('button', { name: language === 'en' ? 'Next' : '다음', exact: true });
      if (!(await next.count()) || await next.isDisabled()) break;
      await next.click();
    } while (reached < report.findings.length);
    expect(reached).toBe(report.findings.length); expect(peak).toBeLessThan(900);
    observations.push({ name, reached, peak });
  }
  await info.attach('scenario-dom', { body: JSON.stringify(observations), contentType: 'application/json' });
});

for (const width of [1280, 390]) for (const language of ['ko', 'en']) test(`reference picker ${width} ${language} pages, explicit assertion, clear, inherit and current-route payloads`, async ({ page }, info) => {
  await page.setViewportSize({ width, height: 900 });
  const { errors, writes } = await install(page, language);
  for (const route of ['/analyses/new', '/analyses/upload', `/analyses/${fixture.jobs.measured.id}`]) {
    await page.goto(route);
    if (!route.endsWith(fixture.jobs.measured.id)) {
      await page.getByLabel('Analysis name').fill('Owned stage3 UI admission');
      await page.getByLabel('Analysis module').selectOption('ddos_attack');
      await page.getByLabel('Minimum observed sources', { exact: true }).fill('3');
      await page.getByLabel('Minimum packets', { exact: true }).fill('6');
      await page.getByLabel('Minimum packets/second', { exact: true }).fill('1');
      await page.getByLabel('Minimum bits/second', { exact: true }).fill('1');
      if (route.endsWith('/new')) await page.getByLabel('Owned offline sensor').check();
      if (route.endsWith('upload')) await page.getByLabel('Capture file').setInputFiles(join(root, 'unmeasured.pcap'));
    }
    const action = page.getByLabel(language === 'en' ? 'Normal reference action' : '정상 참조 작업'); await expect(action).toBeVisible();
    if (route.endsWith(fixture.jobs.measured.id)) {
      expect(await action.inputValue()).toBe('inherit');
      await action.locator('xpath=ancestor::form').evaluate((form: HTMLFormElement) => form.requestSubmit());
      await expect(page.getByText('Server eligibility rejection (browser transport fixture)')).toBeVisible();
      expect(writes.at(-1)!.body).not.toHaveProperty('ddos_normal_reference');
    }
    await action.selectOption('select'); await expect(page.getByRole('radio')).toHaveCount(20);
    expect((await geometry(page)).document).toBeLessThanOrEqual(width);
    await page.getByRole('button', { name: language === 'en' ? 'Next reference page' : '다음 참조 페이지' }).click(); await expect(page.getByRole('radio')).toHaveCount(1);
    await page.getByRole('radio').check();
    await action.locator('xpath=ancestor::form').evaluate((form: HTMLFormElement) => form.requestSubmit());
    await expect(page.getByText('Server eligibility rejection (browser transport fixture)')).toBeVisible();
    expect(writes.at(-1)!.body).toHaveProperty('ddos_normal_reference', { job_id: normal.id, dataset_id: normal.dataset_id });
    await action.selectOption('clear');
    await action.locator('xpath=ancestor::form').evaluate((form: HTMLFormElement) => form.requestSubmit());
    await expect.poll(() => (writes.at(-1)!.body as Record<string, unknown>).ddos_normal_reference).toBeNull();
  }
  expect(errors).toEqual([]);
  writeFileSync(info.outputPath('ui-payloads.json'), JSON.stringify(writes, null, 2));
  const receipt = execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python'), ['tests/ddos_ui_http_smoke.py', root, info.outputPath('ui-payloads.json')], { encoding: 'utf8' });
  await info.attach('real-http-pipeline', { body: receipt, contentType: 'application/json' });
});

async function history(page: Page) {
  await page.route('**/api/v1/analysis-jobs?*', route => route.fulfill({ contentType: 'application/json', body: JSON.stringify({ items: [{ ...fixture.jobs.measured, name: 'Cache A' }, { ...fixture.jobs.unmeasured, name: 'Cache B' }], total: 2 }) }));
}
test('actual App query-cache owners start collapsed after cached A to B to A navigation', async ({ page }) => {
  await install(page, 'en'); await history(page);
  for (const [name, first] of [['Cache A', true], ['Cache B', false], ['Cache A', false]] as const) {
    if (first) await page.goto('/analyses');
    else await page.getByRole('link', { name: 'Back to analysis history' }).click();
    await page.getByRole('link', { name, exact: true }).click();
    await expect(page.getByRole('region', { name: 'DDoS at a glance' })).toBeVisible();
    await expect(page.getByRole('region', { name: 'Candidate inspection' })).toHaveCount(0);
    await expect(page.getByRole('region', { name: 'DDoS finding evidence' })).toHaveCount(0);
    await page.getByRole('button', { name: /Show detailed evidence/ }).first().click();
    await page.getByRole('button', { name: /Inspect candidate/ }).first().click();
    await expect(page.getByRole('region', { name: 'Candidate inspection' })).toHaveCount(1);
  }
});
test('duplicate pending reanalysis is suppressed and its late success cannot navigate a successor owner', async ({ page }) => {
  await install(page, 'en'); await history(page);
  let release!: () => void, calls = 0;
  const gate = new Promise<void>(resolveGate => { release = resolveGate; });
  await page.route('**/api/v1/analysis-jobs/*/reanalyze', async route => {
    calls++; await gate;
    await route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ id: 'late-created-fixture' }) });
  });
  try {
    await page.goto(`/analyses/${fixture.jobs.measured.id}`);
    const action = page.getByLabel('Normal reference action'); await expect(action).toBeVisible();
    await action.locator('xpath=ancestor::form').evaluate((form: HTMLFormElement) => { form.requestSubmit(); form.requestSubmit(); });
    await expect.poll(() => calls).toBe(1);
    await expect(action).toBeDisabled();
    await page.getByRole('link', { name: 'Back to analysis history' }).click();
    await page.getByRole('link', { name: 'Cache B', exact: true }).click();
    await expect(page.getByRole('region', { name: 'DDoS at a glance' })).toBeVisible();
    const response = page.waitForResponse(r => r.url().endsWith('/reanalyze'));
    release(); await response;
    await expect(page).toHaveURL(new RegExp(fixture.jobs.unmeasured.id + '$'));
    expect(calls).toBe(1);
  } finally { release(); }
});
