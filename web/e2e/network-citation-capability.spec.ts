import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { expect, test } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

// Real parser/report + public build_network_input + schema-validated synthetic
// interpretation. Local fixture HTTP only; no model, deployment or native proof.
const fixture = JSON.parse(execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python'), ['tests/network_report_fixture.py', '--maximum'], { encoding: 'utf8', maxBuffer: 20000000 }));
for (const width of [1280, 390]) for (const language of ['en', 'ko']) {
  test(`source-bound citation keyboard and capability ${width}px ${language}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 });
    const errors: string[] = [], requests: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
    await page.addInitScript(lang => { localStorage.setItem('c2hunter-token', 'synthetic-fixture-token'); localStorage.setItem('c2hunter-report-language', lang); }, language);
    const job = (id: string) => ({ id, dataset_id: 'citation-dataset', name: id === 'citation-job' ? 'Citation A' : 'Citation B', status: 'COMPLETED', source_type: id === 'citation-job' ? 'PCAP_UPLOAD' : 'SENSOR_CAPTURE', mode: id === 'citation-job' ? 'PCAP_UPLOAD' : 'LIVE', analysis: { module: 'network_anomaly' }, network_anomaly: fixture.many });
    await page.route('**/api/v1/**', async route => {
      const path = new URL(route.request().url()).pathname.replace('/api/v1', '');
      requests.push(`${route.request().method()} ${path}`);
      let body: unknown = { items: [] };
      if (path === '/analysis-jobs/citation-job' || path === '/analysis-jobs/second-job') body = job(path.split('/').at(-1)!);
      else if (path === '/analysis-jobs') body = { items: [job('citation-job'), job('second-job')] };
      else if (path === '/ai-capabilities') body = { available: true, network_interpretation: true, remote: false, provider: 'fixture', model_name: 'no-inference' };
      else if (path === '/analysis-jobs/citation-job/ai-runs') body = { items: [fixture.run] };
      else if (path === '/ai-runs/citation-run') body = fixture.run;
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify(body) });
    });
    const ko = language === 'ko';
    const measurements: { phase: string; nodes: number; width: number; body: number; document: number }[] = [];
    const measure = async (phase: string) => {
      const geometry = await page.evaluate(() => ({ nodes: document.querySelectorAll('*').length, width: innerWidth, body: document.body.scrollWidth, document: document.documentElement.scrollWidth }));
      expect(geometry.nodes).toBeLessThanOrEqual(2500); expect(geometry.body).toBeLessThanOrEqual(width); expect(geometry.document).toBeLessThanOrEqual(width);
      measurements.push({ phase, ...geometry });
    };
    await page.goto('/analyses/citation-job');
    await expect(page.getByRole('heading', { name: ko ? '이상 징후 관찰됨' : 'Anomaly observed', exact: true })).toBeVisible();
    await expect(page.getByRole('region', { name: ko ? '입력 지원 범위' : 'Source capability', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: /Job details/ })).toHaveAttribute('aria-expanded', 'false');
    await measure('initial');
    for (const key of ['Enter', 'Space']) {
      await page.getByRole('button', { name: ko ? 'AI 해석 열기' : 'Open AI interpretation', exact: true }).click();
      await page.getByRole('button', { name: ko ? 'AI 원문 전체 보기' : 'View full AI text', exact: true }).click();
      await measure('AI full');
      const citation = page.getByRole('article', { name: ko ? 'AI 해석 전체 원문' : 'Full AI interpretation' }).getByRole('button', { name: fixture.many.issues[19].id, exact: true }).first();
      await expect(citation).toBeEnabled(); await citation.focus();
      const before = [...requests]; await page.keyboard.press(key);
      const evidence = page.getByRole('region', { name: ko ? '대표 흐름 증거' : 'Representative flow evidence', exact: true });
      await expect(evidence).toBeFocused(); await expect(evidence).toHaveAttribute('id', 'network-evidence-19'); await expect(evidence).toBeVisible();
      await expect(page.getByText(ko ? '13페이지 중 3페이지' : 'Page 3 of 13', { exact: true })).toBeVisible();
      await expect(page.getByRole('article', { name: ko ? 'AI 해석 전체 원문' : 'Full AI interpretation' })).toHaveCount(0);
      const box = await evidence.boundingBox(); expect(box!.y).toBeLessThan(900); expect(box!.y + box!.height).toBeGreaterThan(0);
      await measure(`citation ${key}`); expect(requests).toEqual(before);
    }
    await page.screenshot({ path: info.outputPath('citation.png'), fullPage: true });
    // Actual cached SPA A→B→A routes, not a reload that hides leaked detail state.
    await page.getByRole('link', { name: 'Back to analysis history' }).click();
    await page.getByRole('link', { name: 'Citation B', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Citation B', exact: true })).toBeVisible();
    await expect(page.locator('[id^="network-evidence-"]')).toHaveCount(0);
    await expect(page.getByRole('region', { name: ko ? '입력 지원 범위' : 'Source capability', exact: true })).toContainText(ko ? '센서 LIVE 출처' : 'Sensor LIVE origin');
    await page.getByRole('link', { name: 'Back to analysis history' }).click();
    await page.getByRole('link', { name: 'Citation A', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Citation A', exact: true })).toBeVisible();
    await expect(page.locator('[id^="network-evidence-"]')).toHaveCount(0); await measure('cached A return');
    await page.goto('/analyses/new');
    await page.getByLabel('Analysis module').selectOption('network_anomaly');
    const disclosure = page.getByRole('region', { name: /Source capability/ });
    await expect(disclosure).toContainText('LIVE aggregate');
    await page.getByLabel('Data source').selectOption('HISTORICAL');
    await expect(disclosure).toContainText('Historical sensor aggregates'); await measure('selection');
    expect(errors).toEqual([]); expect(requests.filter(r => !r.startsWith('GET '))).toEqual([]);
    await info.attach('mounted-geometry', { body: JSON.stringify(measurements), contentType: 'application/json' });
  });
}
test('actual native HISTORICAL public wire and same-PCAP control capability', async ({ page }, info) => {
  test.skip(!process.env.C2HUNTER_NATIVE_CAPABILITY_BUNDLE, 'Parent-generated native bundle must be supplied explicitly.');
  const bytes = readFileSync(process.env.C2HUNTER_NATIVE_CAPABILITY_BUNDLE!);
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  expect(sha256).toBe(process.env.C2HUNTER_NATIVE_CAPABILITY_SHA256);
  const bundle = JSON.parse(bytes.toString());
  expect(bundle.schema_version).toBe('network-native-capability-fixture-v1');
  const errors: string[] = [], writes: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => { localStorage.setItem('c2hunter-token', 'synthetic-fixture-token'); localStorage.setItem('c2hunter-report-language', 'en'); });
  await page.route('**/api/v1/**', async route => {
    if (route.request().method() !== 'GET') writes.push(new URL(route.request().url()).pathname);
    const path = new URL(route.request().url()).pathname;
    const job = [bundle.native.job, bundle.pcap.job].find(j => path === `/api/v1/analysis-jobs/${j.id}`);
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify(job ?? { items: [] }) });
  });
  expect(bundle.native.job.mode).toBe('HISTORICAL'); expect(bundle.native.job.network_anomaly.summary).toMatchObject({ evaluated_records: 0, incomplete_records: 2 });
  await page.goto(`/analyses/${bundle.native.job.id}`);
  await expect(page.getByRole('heading', { name: 'Insufficient data', exact: true })).toBeVisible();
  await expect(page.getByRole('region', { name: 'Source capability' })).toContainText('Historical sensor origin');
  await expect(page.getByRole('region', { name: 'Source capability' })).toContainText('does not transmit network packet-evidence');
  await page.getByRole('button', { name: 'Coverage details and limitations' }).click();
  await expect(page.getByText(/SENSOR_CAPTURE_QUALITY_UNAVAILABLE/)).toBeVisible();
  await expect(page.getByText(/0 evaluated/)).toBeVisible();
  await page.screenshot({ path: info.outputPath('native-historical.png'), fullPage: true });
  await page.goto(`/analyses/${bundle.pcap.job.id}`);
  await expect(page.getByRole('heading', { name: 'Anomaly observed', exact: true })).toBeVisible();
  await expect(page.getByRole('region', { name: 'Source capability' })).toContainText('Uploaded PCAP origin');
  expect(bundle.pcap.job.network_anomaly.summary.evaluated_records).toBe(6);
  await expect(page.getByTestId('top-observation')).toHaveCount(2);
  expect(await page.locator('*').count()).toBeLessThanOrEqual(2500);
  expect(errors).toEqual([]); expect(writes).toEqual([]);
  await info.attach('native-wire-binding', { body: JSON.stringify({ sha256, native_mode: bundle.native.job.mode, pcap_mode: bundle.pcap.job.mode }), contentType: 'application/json' });
});
