import { expect, test, type Page, type TestInfo } from '@playwright/test';
import { fixture } from '../tests/investigationFixtures';
import { producer } from '../tests/jobInvestigationFixtures';
import { savedNavigation } from '../tests/investigationSavedNavigationFixtures';
import type { InvestigationRun } from '../src/investigationTypes';

type Locale = 'ko' | 'en';
const text = (locale: Locale, ko: string, en: string) => locale === 'ko' ? ko : en;
async function prepare(page: Page, width: number, locale: Locale) {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.setViewportSize({ width, height: 900 });
  await page.addInitScript(value => { localStorage.setItem('c2hunter-token', 'recovery-fixture'); localStorage.setItem('c2hunter-report-language', value); }, locale);
  return errors;
}
async function evidence(page: Page, info: TestInfo, name: string, data: unknown) {
  const geometry = await page.evaluate(() => ({ viewport: innerWidth, document: document.documentElement.scrollWidth, nodes: document.querySelectorAll('*').length }));
  expect(geometry.document).toBeLessThanOrEqual(geometry.viewport + 1);
  await page.screenshot({ path: info.outputPath(name + '.png'), fullPage: true });
  await info.attach(name, { contentType: 'application/json', body: JSON.stringify({ geometry, data }) });
}

for (const width of [1280, 390]) for (const locale of ['ko', 'en'] as const) {
  test(`N1 N2 actual App source-error entry and nonterminal polling recovery ${width} ${locale}`, async ({ page }, info) => {
    const errors = await prepare(page, width, locale);
    const queued = { ...fixture('run_queued') as InvestigationRun, revision: 2 };
    let history = queued, sourceAvailable = false, reads = 0;
    const writes: string[] = [], failedCancels: string[] = [], times: number[] = [];
    let release!: () => void;
    const held = new Promise<void>(yes => { release = yes; });
    page.on('requestfailed', request => { if (request.url().endsWith('/cancel')) failedCancels.push(request.url()); });
    await page.route('**/api/v1/**', async route => {
      const request = route.request(), url = new URL(request.url()), path = url.pathname;
      if (request.method() !== 'GET') writes.push(path);
      if (path === '/api/v1/analysis-jobs/job' && !sourceAvailable) return route.fulfill({ status: 503, body: JSON.stringify({ error: { message: 'Source unavailable' } }) });
      if (path.endsWith('/cancel')) { await held; return route.fulfill({ status: 503, body: '{}' }); }
      if (path.endsWith('/' + queued.id)) {
        reads++; times.push(Date.now());
        if (reads === 1) return route.fulfill({ status: 503, body: '{}' });
        return route.fulfill({ json: { ...queued, revision: reads + 2, status: reads >= 3 ? 'CANCELLED' : 'QUEUED' } });
      }
      let body: unknown = { items: [], total: 0 };
      if (path === '/api/v1/analysis-jobs/job') body = { id: 'job', name: 'Recovered source', status: 'COMPLETED', analysis: { module: 'c2' } };
      else if (path.endsWith('/ai-investigations')) body = { items: [history], next_cursor: null };
      else if (path.endsWith('/capabilities')) body = fixture('capabilities');
      else if (path.endsWith('/ai-capabilities')) body = { available: false };
      await route.fulfill({ json: body });
    });
    await page.goto('/analyses/job');
    await page.getByRole('button', { name: text(locale, 'IP 조사 열기', 'Open IP investigation'), exact: true }).click();
    const choose = () => page.getByRole('button', { name: new RegExp('2001:db8::1 · QUEUED') });
    await choose().click();
    await expect(page.getByRole('button', { name: text(locale, '상태 다시 읽기', 'Retry status read'), exact: true })).toBeVisible();
    await page.getByRole('button', { name: text(locale, '조사 취소', 'Cancel investigation'), exact: true }).click();
    await page.getByRole('button', { name: text(locale, '이 조사 취소 확인', 'Confirm cancel this run'), exact: true }).click();
    await expect.poll(() => writes.length).toBe(1);
    sourceAvailable = true;
    await page.getByRole('button', { name: '다시 시도', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Recovered source', exact: true })).toBeVisible();
    const receipt = page.getByRole('region', { name: text(locale, '취소 영수증', 'Cancellation receipt'), exact: true });
    await expect(receipt).toContainText(text(locale, '취소 수락 확인 중', 'Cancellation acknowledgment pending'));
    await expect(page.locator('#ip-investigation-entry form')).toHaveCount(0);
    expect(failedCancels).toEqual([]);
    await evidence(page, info, 'source-recovered-pending', { writes, failedCancels, reads });
    await page.getByRole('button', { name: new RegExp(text(locale, '활성 조사로 돌아가기', 'Return to active investigation')) }).click();
    const selected = page.getByRole('region', { name: text(locale, '선택 조사', 'Selected investigation'), exact: true });
    await expect(selected).toContainText(queued.id);
    release();
    await expect(receipt).toContainText(text(locale, '취소 결과 미확인', 'cancellation unconfirmed'));
    history = { ...queued, revision: 3 };
    await page.getByRole('button', { name: text(locale, '이력 다시 읽기', 'Retry history read'), exact: true }).click();
    await choose().click();
    await expect.poll(() => reads).toBe(2);
    await expect(page.getByRole('button', { name: text(locale, '상태 다시 읽기', 'Retry status read'), exact: true })).toHaveCount(0);
    await expect(selected).toContainText('CANCELLED');
    expect(reads).toBe(3);
    expect(times[2] - times[1]).toBeGreaterThanOrEqual(1900);
    await expect(receipt.getByRole('button', { name: text(locale, '관측된 종료 상태 확인', 'Acknowledge observed terminal outcome'), exact: true })).toBeVisible();
    await evidence(page, info, 'poll-recovered-terminal-observation', { writes, failedCancels, reads, times, errors });
    expect(writes).toEqual([`/api/v1/analysis-jobs/job/ai-investigations/${queued.id}/cancel`]);
    expect(errors).toEqual([]); expect(failedCancels).toEqual([]);
  });

  for (const kind of ['IP', 'Job'] as const) test(`N3 ${kind} lost cancel ACK reconciles validated history explicitly ${width} ${locale}`, async ({ page }, info) => {
    const errors = await prepare(page, width, locale), ip = kind === 'IP';
    const suffix = ip ? 'ai-investigations' : 'ai-job-investigations';
    const queued = { ...(ip ? fixture('run_queued') as InvestigationRun : JSON.parse(producer.fixtures.run_queued)), revision: 2 };
    const cancelled = { ...queued, status: 'CANCELLED', revision: 3 };
    const other = { ...queued, id: 'f'.repeat(64) };
    const saved = { ...(ip ? savedNavigation.ip : savedNavigation.job), id: 'e'.repeat(64) };
    let history = queued;
    const writes: string[] = [];
    await page.route('**/api/v1/**', async route => {
      const request = route.request(), path = new URL(request.url()).pathname;
      if (request.method() !== 'GET') writes.push(path);
      if (path.endsWith('/cancel')) return route.fulfill({ status: 503, body: '{}' });
      let body: unknown = { items: [], total: 0 };
      if (path === '/api/v1/analysis-jobs/job') body = { id: 'job', name: 'Terminal reconciliation', status: 'COMPLETED', analysis: { module: 'c2' } };
      else if (path.endsWith('/' + suffix)) body = { items: [history], next_cursor: null };
      else if (path.endsWith('/' + queued.id) || path.endsWith('/' + other.id)) body = path.endsWith('/' + queued.id) ? queued : other;
      else if (path.includes('/evidence/')) body = (ip ? savedNavigation.ipEvidence : savedNavigation.jobEvidence)[path.split('/').at(-1)!];
      else if (path.endsWith('/capabilities')) body = ip ? fixture('capabilities') : JSON.parse(producer.fixtures.capabilities);
      else if (path.endsWith('/ai-capabilities')) body = { available: false };
      await route.fulfill({ json: body });
    });
    await page.goto('/analyses/job');
    await page.getByRole('button', { name: text(locale, 'AI 조사', 'AI investigation'), exact: true }).click();
    await page.getByRole('button', { name: ip ? text(locale, 'IP 조사 열기', 'Open IP investigation') : text(locale, '실험적 조사 열기', 'Open experimental investigation'), exact: true }).click();
    const choose = () => page.getByRole('button', { name: ip ? /2001:db8::1 ·/ : new RegExp(text(locale, '저장된 조사 보기', 'View saved run')) });
    await choose().click();
    const cancel = async () => {
      await page.getByRole('button', { name: ip ? text(locale, '조사 취소', 'Cancel investigation') : text(locale, '이 조사 취소 요청', 'Request cancellation of this run'), exact: true }).click();
      if (ip) await page.getByRole('button', { name: text(locale, '이 조사 취소 확인', 'Confirm cancel this run'), exact: true }).click();
    };
    const refresh = async (value: typeof history) => {
      history = value;
      await page.getByRole('button', { name: ip ? text(locale, '이력 다시 읽기', 'Retry history read') : text(locale, '처음 이력 / 다시 읽기', 'First history / Refresh'), exact: true }).click();
      await expect(choose()).toContainText(value.status);
      await choose().click();
    };
    await cancel();
    const receipt = page.getByRole('region', { name: text(locale, '취소 영수증', 'Cancellation receipt'), exact: true });
    await expect(receipt).toContainText(text(locale, '취소 결과 미확인', 'cancellation unconfirmed'));
    await refresh(cancelled);
    await expect(receipt).toContainText('CANCELLED');
    await expect(receipt).toContainText(text(locale, '원래 취소 수락 응답은 여전히 미확인입니다', 'Original cancellation acknowledgment remains unknown'));
    await refresh(saved);
    const run = page.getByRole('region', { name: ip ? text(locale, '선택 조사', 'Selected investigation') : text(locale, '저장된 작업 조사', 'Saved job investigation'), exact: true });
    if (ip) await run.getByRole('button', { name: text(locale, '발급된 근거', 'Issued evidence'), exact: true }).click();
    else await run.getByRole('button', { name: text(locale, '피어 상세 ', 'Peer details ') + savedNavigation.job.selection.peer_ids[0], exact: true }).click();
    await run.getByRole('button', { name: new RegExp('^' + text(locale, '근거 ', 'Evidence ')) }).first().click();
    const detail = page.getByRole(width === 390 ? 'dialog' : 'region', { name: text(locale, '선택 근거', 'Selected evidence'), exact: true });
    await expect(detail).toBeVisible();
    const ack = (width === 390 ? detail : page).getByRole('button', { name: text(locale, '관측된 종료 상태 확인', 'Acknowledge observed terminal outcome'), exact: true });
    await expect(ack).toBeVisible();
    await evidence(page, info, 'observed-terminal-acknowledgment', { kind, writes, errors });
    await ack.click();
    await expect(detail).toBeVisible();
    // Desktop receipt is outside the inline detail; Escape belongs to its focused region.
    if (width === 1280) await detail.getByRole('heading', { name: text(locale, '선택 근거', 'Selected evidence'), exact: true }).focus();
    await page.keyboard.press('Escape');
    await expect(detail).toHaveCount(0);
    await refresh(other);
    await cancel();
    await expect.poll(() => writes.length).toBe(2);
    expect(writes).toEqual([`/api/v1/analysis-jobs/job/${suffix}/${queued.id}/cancel`, `/api/v1/analysis-jobs/job/${suffix}/${other.id}/cancel`]);
    expect(errors).toEqual([]);
    await evidence(page, info, 'subsequent-run-cancellation', { kind, writes, errors });
  });
}
