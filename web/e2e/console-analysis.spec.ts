import { expect, test, type Locator, type Page } from '@playwright/test';
import { installApiFixture } from './route-fixture';
import { withLegacyAuthentication } from './auth-fixture';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// Render the built App (including main.tsx CSS). HTTP fixtures are not live
// capture, model, or deployment acceptance. No injected stylesheet or DOM.
async function openFixture(page: Page, path: string, language = 'en') {
  await installApiFixture(page);
  await page.addInitScript(lang => {
    localStorage.setItem('c2hunter-token', 'console-analysis-fixture');
    localStorage.setItem('c2hunter-report-language', lang);
  }, language);
  await page.goto(path);
}

async function fitsViewport(locator: Locator) {
  const geometry = await locator.evaluate(element => {
    const box = element.getBoundingClientRect();
    return { left: box.left, right: box.right, width: innerWidth, client: element.clientWidth, scroll: element.scrollWidth };
  });
  expect(geometry.left).toBeGreaterThanOrEqual(0);
  expect(geometry.right).toBeLessThanOrEqual(geometry.width + 1);
  expect(geometry.scroll).toBeLessThanOrEqual(geometry.client + 1);
}

for (const width of [1280, 390]) for (const language of ['en', 'ko']) {
  test(`C2 inset facts and quiet purpose navigation ${width} ${language}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 });
    await openFixture(page, '/analyses/job-1', language);
    const summary = page.locator('.c2-result-summary');
    await expect(summary).toBeVisible();
    await page.screenshot({ path: info.outputPath('c2-summary.png'), fullPage: true });
    const fact = summary.locator('.c2-key-facts li').first();
    await expect(fact).toHaveCSS('border-top-width', '0px');
    await expect(fact).toHaveCSS('background-color', 'rgb(32, 36, 42)');
    await expect(summary.locator('.c2-next-check')).toHaveCSS('border-left-width', '0px');
    const navigation = page.locator('.c2-purpose-nav');
    await expect(navigation.locator('[aria-pressed="false"]').first()).toHaveCSS('background-color', 'rgba(0, 0, 0, 0)');
    for (const control of await navigation.getByRole('button').all()) await fitsViewport(control);
    const work = navigation.getByRole('button', { name: language === 'en' ? 'Work information' : '작업 정보', exact: true });
    await work.click();
    await expect(work).toHaveAttribute('aria-pressed', 'true');
    await expect(navigation.locator('[aria-pressed="true"]')).toHaveCount(1);
    await fitsViewport(summary);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
  });
}

const candidateId = `candidate-${'abcdef0123456789'.repeat(16)}/part?query#fragment%`;
const candidate = {
  id: candidateId, job_id: 'job-1', candidate_ip: '2001:db8:abcd:1234:5678:90ab:cdef:1234',
  score: 87, severity: 'HIGH', workflow_status: 'NEEDS_REVIEW', action_status: 'NOT_REQUIRED',
  flow_count: 600, packet_count: 6000, byte_count: 65536, traffic_series: [2, 4, 3, 12, 8, 20],
  evidence: Array.from({ length: 4 }, (_, index) => ({
    type: 'PERIODIC_BEACON', description: `Retained observation ${index + 1}`, score: 14,
    metrics: { sample_count: 50, period_seconds: 30, source_identifier: 'source-'.repeat(32) },
    warnings: index === 3 ? ['Evidence coverage is incomplete'] : [],
  })),
};

for (const width of [1280, 390]) {
  test(`candidate inset summary and owned inspector ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 });
    const writes: string[] = [], errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await openFixture(page, '/candidates/candidate-1');
    await page.route('**/api/v1/**', withLegacyAuthentication(async route => {
      const path = new URL(route.request().url()).pathname;
      if (route.request().method() !== 'GET') writes.push(path);
      if (path === `/api/v1/candidates/${encodeURIComponent(candidateId)}`) return route.fulfill({ json: candidate });
      return route.fallback();
    }));
    await page.goto(`/candidates/${encodeURIComponent(candidateId)}?q=retained&page=4`);
    const summary = page.getByRole('region', { name: 'Candidate result summary' });
    await expect(summary.getByText('Evidence coverage is incomplete')).toBeVisible();
    const navigation = page.getByRole('navigation', { name: 'Candidate detail selection' });
    await page.screenshot({ path: info.outputPath('candidate-summary.png'), fullPage: true });
    await expect.soft(summary.locator('.metrics article').first()).toHaveCSS('border-top-width', '0px');
    await expect.soft(navigation.getByRole('button', { name: 'Network context', exact: true })).toHaveCSS('background-color', 'rgba(0, 0, 0, 0)');
    await page.getByLabel('Evidence selection').selectOption('3');
    const inspector = page.locator('.candidate-detail-surface');
    await expect(inspector).toContainText('Retained observation 4');
    await expect(inspector.getByText('Evidence coverage is incomplete')).toBeVisible();
    await page.screenshot({ path: info.outputPath('candidate-inspector.png'), fullPage: true });
    await expect(inspector.locator(':scope > .panel').first()).toHaveCSS('border-top-width', '0px');
    await expect(inspector.locator(':scope > .section-heading')).toHaveCSS('border-bottom-width', '1px');
    await fitsViewport(inspector);
    if (width === 390) await expect(inspector).toHaveAttribute('role', 'dialog');
    else await expect(inspector).toHaveAttribute('role', 'region');
    await page.keyboard.press('Escape');
    await expect(page.getByLabel('Evidence selection')).toBeFocused();
    await expect(page).toHaveURL(/\?q=retained&page=4$/);
    await page.locator('details.candidate-identifier > summary').click();
    const identifier = page.locator('.candidate-identifier .record-id');
    await expect(identifier).toHaveText(`Candidate ${candidateId}`);
    await fitsViewport(identifier);
    for (const control of await navigation.locator('button, select').all()) await fitsViewport(control);
    await navigation.getByRole('button', { name: 'Raw candidate', exact: true }).click();
    const raw = page.getByLabel('Retained candidate JSON');
    expect(JSON.parse(await raw.innerText())).toEqual(candidate);
    await fitsViewport(raw);
    await page.keyboard.press('Escape');
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    expect(writes).toEqual([]);
    expect(errors).toEqual([]);
  });
}

// Existing real parser/producer and retained PCAP fixtures, intercepted HTTP.
const python = process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python');
const network = JSON.parse(execFileSync(python, ['tests/network_report_fixture.py', '--glance'], { encoding: 'utf8' }));
const ddosJob = JSON.parse(readFileSync(new URL('../../controller/tests/fixtures/pcap_attack_guidance/positive.job.json', import.meta.url), 'utf8'));

for (const width of [1280, 390]) for (const language of ['en', 'ko']) for (const kind of ['network', 'ddos']) {
  test(`${kind} restrained progressive report ${width} ${language}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 });
    const errors: string[] = [], writes: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await openFixture(page, '/analyses/job-1', language);
    const job = kind === 'network'
      ? { id: 'console-network', name: 'Network observation review', status: 'COMPLETED', analysis: { module: 'network_anomaly' }, network_anomaly: network.many }
      : ddosJob;
    await page.route('**/api/v1/**', withLegacyAuthentication(async route => {
      const path = new URL(route.request().url()).pathname;
      if (route.request().method() !== 'GET') writes.push(path);
      if (path === `/api/v1/analysis-jobs/${job.id}`) return route.fulfill({ json: job });
      if (path === `/api/v1/analysis-jobs/${job.id}/ai-runs`) return route.fulfill({ json: { items: [], total: 0 } });
      return route.fallback();
    }));
    await page.goto(`/analyses/${job.id}`);
    const en = language === 'en';
    const report = page.locator(kind === 'network' ? '.network-report' : '.ddos-report');
    const glance = report.locator('.network-glance');
    const next = report.locator(kind === 'network' ? '.network-next-action' : '.ddos-next');
    await expect(glance).toBeVisible();
    await page.screenshot({ path: info.outputPath(`${kind}-overview.png`), fullPage: true });
    await expect.soft(glance).toHaveCSS('border-top-width', '0px');
    await expect.soft(next).toHaveCSS('border-left-width', '0px');
    await expect(next).toHaveCSS('background-color', 'rgb(32, 36, 42)');
    const nextBox = (await next.boundingBox())!;
    expect(nextBox.y + nextBox.height).toBeLessThanOrEqual(900);
    if (kind === 'network') {
      await expect(report.getByTestId('top-observation')).toHaveCount(3);
      await expect(report.locator('.network-totals > div').first()).toHaveCSS('border-top-width', '0px');
      await report.getByRole('button', { name: /Inspect evidence|근거 확인/ }).first().click();
      const selector = page.getByLabel(en ? 'Representative example' : '대표 예시', { exact: true });
      await selector.selectOption('0');
      const detail = page.locator('.network-example-detail');
      await expect(detail).toBeVisible();
      await page.screenshot({ path: info.outputPath('network-inspector.png'), fullPage: true });
      await expect(detail).toHaveCSS('border-radius', '6px');
      await fitsViewport(detail);
      await fitsViewport(detail.getByRole('button', { name: en ? 'Close example detail' : '예시 상세 닫기', exact: true }));
      await page.keyboard.press('Escape');
      await expect(selector).toBeFocused();
    } else {
      const warning = glance.getByText(en ? /No qualified baseline; possible only/ : /적격 기준선 없음; 가능성 수준만 평가/);
      await expect(warning).toBeVisible();
      const warningBox = (await warning.boundingBox())!;
      expect(warningBox.y + warningBox.height).toBeLessThanOrEqual(nextBox.y);
      const trigger = next.getByRole('button');
      await trigger.click();
      const detail = page.locator('.ddos-responsive-detail');
      await expect(detail).toBeVisible();
      await page.screenshot({ path: info.outputPath('ddos-inspector.png'), fullPage: true });
      await expect(detail).toHaveCSS('background-color', 'rgb(32, 36, 42)');
      await expect(report.locator(':scope > article').first()).toHaveCSS('border-left-width', '0px');
      await fitsViewport(detail);
      await fitsViewport(detail.getByRole('button', { name: en ? 'Close detail' : '상세 닫기', exact: true }));
      await page.keyboard.press('Escape');
      await expect(trigger).toBeFocused();
    }
    await fitsViewport(report);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    expect(errors).toEqual([]);
    expect(writes).toEqual([]);
  });
}
