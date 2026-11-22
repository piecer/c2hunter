import { expect, test, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { installApiFixture } from './route-fixture';

// Producer reports, ordinary small transport fixture: not a maximum payload claim.
const reports = JSON.parse(execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python'), ['tests/network_report_fixture.py'], { encoding: 'utf8' }));
const ddos = JSON.parse(readFileSync(new URL('../tests/fixtures/ddos-report-contract.json', import.meta.url), 'utf8'));
const jobs = [
  { id: 'history-c2', name: 'C2 zero', analysis: { module: 'c2' }, candidate_count: 0, packet_count: 0, flow_count: 0 },
  { id: 'history-network', name: 'Network observed', analysis: { module: 'network_anomaly' }, network_anomaly: reports.cap_plus },
  { id: 'history-ddos', name: 'DDoS observed', analysis: { module: 'ddos_attack' }, ddos_attack_summary: { verdict: ddos.verdict, confidence: ddos.confidence, finding_count: ddos.summary.finding_count, primary_attack_type: ddos.summary.primary_attack_type, primary_objective: ddos.summary.primary_objective, coverage_complete: ddos.summary.coverage_complete } },
  { id: 'history-old', name: 'Old network', analysis: { module: 'network_anomaly' }, candidate_count: 0 },
].map(job => ({ ...job, status: 'COMPLETED' }));
async function install(page: Page) {
  await page.addInitScript(() => { localStorage.setItem('c2hunter-token', 'test'); localStorage.setItem('c2hunter-report-language', 'en'); });
  const errors: string[] = [], writes: { path: string; body: unknown }[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await installApiFixture(page);
  await page.route('**/api/v1/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname;
    if (request.method() !== 'GET') {
      writes.push({ path, body: request.postDataJSON() });
      return route.fulfill({ status: 503, json: { error: { message: 'Retained fixture admission' } } });
    }
    if (path === '/api/v1/analysis-jobs') return route.fulfill({ json: { items: jobs, page: 1, page_size: 50, total: jobs.length } });
    if (path === '/api/v1/detector-weight-presets') return route.fulfill({ json: { items: [] } });
    return route.fallback();
  });
  return { errors, writes };
}
async function measure(page: Page, width: number, limit: number) {
  const result = await page.evaluate(() => ({ nodes: document.querySelectorAll('*').length, document: document.documentElement.scrollWidth, body: document.body.scrollWidth }));
  expect(result.nodes).toBeLessThanOrEqual(limit);
  expect(result.document).toBeLessThanOrEqual(width);
  expect(result.body).toBeLessThanOrEqual(width);
  return result;
}
for (const width of [1280, 390]) {
  test(`History reads module-specific successful summaries at ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 });
    const { errors, writes } = await install(page);
    await page.goto('/analyses');
    const table = page.getByRole('table', { name: 'Analysis history' });
    await expect(table.getByRole('row')).toHaveCount(5);
    await expect(table.getByRole('row').nth(1)).toContainText('0 candidates');
    await expect(table.getByRole('row').nth(2)).toContainText(`${reports.cap_plus.summary.issue_count} Network issues`);
    await expect(table.getByRole('row').nth(2)).toContainText('Counts are lower bounds');
    await expect(table.getByRole('row').nth(3)).toContainText(`${ddos.summary.finding_count} DDoS findings`);
    await expect(table.getByRole('row').nth(4)).toContainText('Network summary unavailable');
    await expect(table.getByRole('row').nth(4)).not.toContainText('candidates');
    const initial = await measure(page, width, 1200);
    // Local table scrolling, not clipped/off-screen document overflow.
    const wrap = table.locator('..');
    await page.getByRole('button', { name: 'Edit Old network', exact: true }).scrollIntoViewIfNeeded();
    await wrap.evaluate(element => { element.scrollLeft = element.scrollWidth; });
    await expect(page.getByRole('button', { name: 'Edit Old network', exact: true })).toBeInViewport();
    await wrap.evaluate(element => { element.scrollLeft = 0; });
    await page.getByRole('link', { name: 'Old network', exact: true }).focus();
    await expect(page.getByRole('link', { name: 'Old network', exact: true })).toBeFocused();
    const sequential = await measure(page, width, 2500);
    expect(writes).toEqual([]); expect(errors).toEqual([]);
    await info.attach('history-observed', { body: JSON.stringify({ initial, sequential }), contentType: 'application/json' });
  });
  for (const route of ['/analyses/new', '/analyses/upload']) for (const module of ['c2', 'network_anomaly', 'ddos_attack']) {
    test(`Required-first ${route} ${module} keyboard and payload ${width}`, async ({ page }, info) => {
      await page.setViewportSize({ width, height: 900 });
      const { errors, writes } = await install(page);
      await page.goto(route);
      const upload = route.endsWith('upload');
      await page.getByLabel('Analysis module').selectOption(module);
      await page.getByLabel('Analysis name').fill('Browser stage5 input');
      if (upload) await page.getByLabel('Capture file').setInputFiles({ name: 'owned.pcap', mimeType: 'application/vnd.tcpdump.pcap', buffer: Buffer.from('owned fixture bytes') });
      else await page.getByRole('checkbox', { name: 'Sensor A', exact: true }).check();
      await page.evaluate(() => scrollTo(0, 0));
      const button = page.getByRole('button', { name: upload ? 'Upload and analyze' : 'Start analysis', exact: true });
      const boxes = [];
      for (const control of [page.getByLabel('Analysis name'), page.getByLabel('Analysis module'), page.getByLabel(upload ? 'Capture file' : 'Data source'), page.getByLabel(upload && module === 'ddos_attack' ? 'Protected-side networks' : 'Internal networks'), page.getByRole('status', { name: 'Submission phase' }), button]) {
        const box = await control.boundingBox();
        expect(box).not.toBeNull();
        expect(box!.y).toBeGreaterThanOrEqual(0);
        expect(box!.y + box!.height).toBeLessThanOrEqual(900);
        boxes.push(box);
      }
      const initial = await measure(page, width, 1200);
      const advanced = page.locator('.input-advanced');
      const summary = advanced.locator('summary');
      await expect(advanced).not.toHaveAttribute('open');
      if (module !== 'c2') {
        const limits = page.getByRole('region', { name: 'Interpretation limits' });
        await expect(limits).toBeVisible();
        for (const semantic of module === 'ddos_attack'
          ? [/Source addresses are observations, not confirmed attackers/, /missing baseline.*possible/i, /not attribute actors/, /prove service impact/, /application-layer/, /execute mitigations/]
          // Match the original detailed-help interpretation/capture checklist while
          // Advanced is closed; hidden detailed text cannot satisfy this region.
          : [/A single vantage point cannot prove path loss or its location/, /Missing evidence.*not.*zero anomalies/, /packet-level PCAP/i, /timestamps/, /both directions/, /Aggregated.*missing packet-level/, /ICMP echo RTT is not supplied by the current modern producer/, /TCP RTT requires eligible sequence\/ACK matches and timestamps/, /capture directions and BPF filters broad enough to include replies/]) {
          await expect.soft(limits).toContainText(semantic);
          if (module === 'network_anomaly') {
            await expect(advanced.getByRole('heading', { name: 'Network observations and capture evidence', includeHidden: true }).locator('..')).toContainText(semantic);
          }
        }
        const box = await limits.boundingBox();
        expect(box).not.toBeNull();
        expect(box!.y).toBeGreaterThanOrEqual(0);
        expect(box!.y + box!.height).toBeLessThanOrEqual(900);
        expect(box!.x).toBeGreaterThanOrEqual(0);
        expect(box!.x + box!.width).toBeLessThanOrEqual(width);
        expect(await limits.evaluate(element => parseFloat(getComputedStyle(element).fontSize))).toBeGreaterThanOrEqual(13);
        boxes.push(box);
      }
      if (module === 'c2') await expect(page.getByLabel('Minimum score')).toBeHidden();
      await page.screenshot({ path: info.outputPath('initial-required-and-limits.png') });
      await button.focus(); await page.keyboard.press('Enter');
      await expect(page.getByText('Retained fixture admission', { exact: true })).toBeVisible();
      await expect(page.getByRole('status', { name: 'Submission phase' })).toContainText('Next: 오류와 기존 작업 상태를 확인한 뒤 재시도하세요.');
      expect(writes).toHaveLength(1);
      await summary.focus(); await page.keyboard.press('Enter');
      await expect(advanced).toHaveAttribute('open');
      await page.keyboard.press('Tab');
      await expect(upload ? page.getByLabel('Analyst note') : module === 'ddos_attack' ? page.getByLabel('Packet peak bucket (seconds)') : page.getByLabel('Maximum packets')).toBeFocused();
      if (upload) await page.getByLabel('Analyst note').fill('Retained browser note');
      else { await page.getByLabel('BPF filter').fill('tcp'); await page.getByLabel('Store PCAP', { exact: true }).uncheck(); }
      if (module === 'c2') { await page.getByLabel('Minimum score').fill('0'); await page.getByRole('spinbutton', { name: '공통 목적지 가중치', exact: true }).fill('0'); }
      if (module === 'ddos_attack') await page.getByLabel('Maximum SYN response ratio').fill('0');
      const sequential = [await measure(page, width, 2500)];
      const form = page.locator('.analysis-input-form');
      const edited = await form.evaluate((element: HTMLFormElement) => [...new FormData(element)].map(([key, value]) => [key, typeof value === 'string' ? value : value.name]));
      for (let i = 0; i < 3; i++) {
        await summary.focus(); await page.keyboard.press('Enter');
        sequential.push(await measure(page, width, 2500));
      }
      await expect(advanced).not.toHaveAttribute('open');
      expect(await form.evaluate((element: HTMLFormElement) => [...new FormData(element)].map(([key, value]) => [key, typeof value === 'string' ? value : value.name]))).toEqual(edited);
      expect(writes).toHaveLength(1);
      await button.focus(); await page.keyboard.press('Enter');
      await expect.poll(() => writes.length).toBe(2);
      const expected = structuredClone(writes[0].body) as Record<string, unknown>;
      const actual = writes[1].body as Record<string, unknown>;
      expected.idempotency_key = actual.idempotency_key;
      if (upload) expected.description = 'Retained browser note';
      else { expected.start_time = actual.start_time; expected.end_time = actual.end_time; expected.capture = { ...(expected.capture as object), bpf_filter: 'tcp', store_pcap: false }; }
      if (module === 'c2') {
        const fields = await page.locator('[name^="weight_"]').evaluateAll(inputs => Object.fromEntries(inputs.map(input => [(input as HTMLInputElement).name.slice(7), Number((input as HTMLInputElement).value)])));
        expected.analysis = { ...(expected.analysis as object), minimum_candidate_score: 0, detector_weights: fields };
      }
      if (module === 'ddos_attack') expected.analysis = { ...(expected.analysis as object), ddos_response_ratio_max: 0 };
      expect(actual).toEqual(expected);
      expect(errors).toEqual([]);
      await page.screenshot({ path: info.outputPath('required-first.png'), fullPage: true });
      await info.attach('geometry-and-wire', { body: JSON.stringify({ initial, sequential, boxes, writes }), contentType: 'application/json' });
    });
  }
}
