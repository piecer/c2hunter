import { withLegacyAuthentication } from './auth-fixture';
import { expect, test } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

// Real admission warning and saved GET projection; intercepted browser transport.
const python = process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python');
const reports = JSON.parse(execFileSync(python, ['tests/network_report_fixture.py', '--maximum'], { encoding: 'utf8', maxBuffer: 20000000 }));
const envelope = JSON.parse(execFileSync(python, ['tests/network_public_job_fixture.py'], { input: JSON.stringify(reports.many), encoding: 'utf8', maxBuffer: 20000000 }));
const witness = JSON.parse(execFileSync(python, ['tests/network_saved_warning_fixture.py'], { input: JSON.stringify(envelope), encoding: 'utf8', maxBuffer: 20000000 }));
const unknown = 'Future source qualifier: sensor timing is unverified; do not assume complete observation.';
// Even a familiar-looking operational prefix must not be a hiding whitelist.
const operational = envelope.warnings[0];

for (const width of [1280, 390]) for (const language of ['en', 'ko']) for (const era of ['job', 'legacy'] as const) {
  test(`saved ${era} source warning remains qualified outside disclosure ${width}px ${language}`, async ({ page }, info) => {
    const ko = language === 'ko';
    await page.setViewportSize({ width, height: 900 });
    await page.addInitScript(language => {
      localStorage.setItem('c2hunter-token', 'saved-warning-fixture');
      localStorage.setItem('c2hunter-report-language', language);
    }, language);
    const requests: string[] = [], errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    const job = { ...witness[era], warnings: [...witness[era].warnings, unknown] };
    await page.route('**/api/v1/**', withLegacyAuthentication(async route => {
      const path = new URL(route.request().url()).pathname.replace('/api/v1', '');
      requests.push(`${route.request().method()} ${path}`);
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify(path === `/analysis-jobs/${job.id}` ? job : { items: [] }) });
    }));
    await page.goto(`/analyses/${job.id}`);
    const glance = page.getByRole('region', { name: ko ? '한눈에 보기' : 'At a glance', exact: true });
    if (era === 'job') await expect(glance).toBeVisible();
    else await expect(page.getByRole('heading', { name: ko ? '이전 형식 보고서' : 'Legacy report', exact: true })).toBeVisible();
    await page.screenshot({ path: info.outputPath('saved-warning-before-assertions.png'), fullPage: true });
    await info.attach('producer-witness', { body: JSON.stringify(witness), contentType: 'application/json' });
    expect(job.network_anomaly.warnings).not.toContain('CAPTURE_PACKET_LIMIT_REACHED');
    const limitation = page.getByText(ko ? '캡처 제한: 패킷 3개 보존 · 2개 제외. 제외된 트래픽은 분석되지 않았습니다.' : 'Capture limit: 3 packets retained · 2 excluded. Excluded traffic was not analyzed.', { exact: true });
    await expect(limitation).toBeVisible();
    const bounds = [];
    const reportEssentials = era === 'job'
      ? [glance.getByTestId('network-verdict'), glance.getByText(ko ? /보고서 일부 생략:/ : /Report truncated:/), glance.getByRole('region', { name: ko ? '다음 행동' : 'Next action' })]
      : [page.getByText(ko ? '이 저장된 보고서에는 종합 판정이 없습니다. 패턴 우선 보고서를 생성하려면 분석을 다시 실행하세요.' : 'An overall verdict is unavailable for this saved report. Re-run analysis to produce a pattern-first report.', { exact: true })];
    for (const locator of [limitation, ...reportEssentials]) {
      const box = await locator.boundingBox(); bounds.push(box);
      expect(box).not.toBeNull(); expect(box!.y).toBeGreaterThanOrEqual(0);
      expect(box!.y + box!.height).toBeLessThanOrEqual(900);
    }
    const warnings = page.getByRole('region', { name: ko ? '원본 작업 경고' : 'Original job warnings', exact: true });
    for (const text of [witness.warning, operational, unknown]) await expect(warnings.getByText(text, { exact: true })).toBeVisible();
    expect(await warnings.evaluate(node => Boolean(node.closest('details,[hidden],[aria-hidden="true"]')))).toBe(false);
    await expect(page.getByRole('button', { name: ko ? '작업 정보' : 'Work information', exact: true })).toHaveAttribute('aria-expanded', 'false');
    expect(await page.locator('*').count()).toBeLessThan(500);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.getByRole('button', { name: ko ? '작업 정보' : 'Work information', exact: true }).click();
    const work = page.getByRole('region', { name: ko ? '작업 정보' : 'Work information', exact: true });
    for (const text of [job.name, job.description, job.id, job.dataset_id, ...job.warnings]) await expect(work.getByText(text, { exact: true })).toBeVisible();
    for (const text of [job.source.filename, job.source.sha256]) await expect(page.getByText(text, { exact: true })).toBeVisible();
    await info.attach('saved-warning-bounds', { body: JSON.stringify(bounds), contentType: 'application/json' });
    expect(errors).toEqual([]); expect(requests.every(request => request.startsWith('GET '))).toBe(true);
  });
}
