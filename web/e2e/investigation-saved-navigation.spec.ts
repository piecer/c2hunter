import { expect, test, type Page } from '@playwright/test';
import { savedNavigation } from '../tests/investigationSavedNavigationFixtures';
import { fixture } from '../tests/investigationFixtures';
import { producer } from '../tests/jobInvestigationFixtures';

type Kind = 'ip' | 'job';
type Locale = 'ko' | 'en';
const title = (kind: Kind, locale: Locale) => kind === 'ip' ? locale === 'ko' ? '선택 조사' : 'Selected investigation' : locale === 'ko' ? '저장된 작업 조사' : 'Saved job investigation';
async function install(page: Page, kind: Kind, locale: Locale, configured = false) {
  const writes: string[] = [], reads: string[] = [], errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(value => { localStorage.setItem('c2hunter-token', 'saved-navigation-fixture'); localStorage.setItem('c2hunter-report-language', value); }, locale);
  const saved = kind === 'ip' ? savedNavigation.ip : savedNavigation.job;
  const older = kind === 'ip' ? fixture('run_failed') : JSON.parse(producer.additional.run_three_facts);
  await page.route('**/api/v1/**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname;
    if (request.method() !== 'GET') writes.push(request.postData() ?? path); else reads.push(path + url.search);
    let body: unknown;
    if (path === '/api/v1/analysis-jobs/job') body = {
      id: 'job', dataset_id: 'dataset', name: 'Saved result with long source metadata '.repeat(5),
      description: 'Analyst note retained separately from investigation results. '.repeat(8),
      status: 'COMPLETED', source_type: 'PCAP_UPLOAD', analysis: { module: 'c2' },
      processing: { phase: 'COMPLETED', phase_started_at: '2026-11-15T00:01:02Z' },
      source: { filename: 'saved-investigation-long-source.pcap', size_bytes: 65536, captured_packet_count: 2000, parsed_packet_count: 1000, skipped_packet_count: 1000, sha256: 'a'.repeat(64) },
      warnings: ['Fixture coverage limitation: some packets were not parsed.'], packet_count: 1000, flow_count: 61, candidate_count: 1,
      start_time: '2026-11-15T00:00:00Z', end_time: '2026-11-15T00:01:00Z',
    };
    else if (path.endsWith('/candidates')) body = { items: [{ id: 'saved-candidate', candidate_ip: '2001:db8::1', score: 42, severity: 'MEDIUM' }], page: 1, page_size: Number(url.searchParams.get('page_size') ?? 25), total: 1 };
    else if (path.endsWith('/capabilities')) {
      const cap = kind === 'ip' ? fixture('capabilities') : JSON.parse(producer.fixtures.capabilities);
      body = { ...(cap as object), availability: configured ? 'CONFIGURED_NOT_PROBED' : 'UNAVAILABLE' };
    }
    else if (path.endsWith(kind === 'ip' ? '/ai-investigations' : '/ai-job-investigations')) body = url.searchParams.has('after') ? { items: [saved], next_cursor: null } : { items: [older], next_cursor: (older as { id: string }).id };
    else if (path.includes('/evidence/')) body = (kind === 'ip' ? savedNavigation.ipEvidence : savedNavigation.jobEvidence)[path.split('/').at(-1)!];
    else if (path.endsWith('/ai-capabilities')) body = { available: false };
    else body = { items: [], total: 0 };
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify(body) });
  });
  await page.goto('/analyses/job');
  await page.getByRole('button', { name: locale === 'ko' ? 'AI 조사' : 'AI investigation', exact: true }).click();
  await page.getByRole('button', { name: kind === 'ip' ? locale === 'ko' ? 'IP 조사 열기' : 'Open IP investigation' : locale === 'ko' ? '실험적 조사 열기' : 'Open experimental investigation', exact: true }).click();
  return { writes, reads, errors, saved };
}

for (const kind of ['ip', 'job'] as const) for (const width of [1280, 390, 640]) for (const locale of ['ko', 'en'] as const) {
  test(`saved ${kind} bounded navigation, citations and metadata ${width} ${locale}`, async ({ page }, testInfo) => {
    // 640×450 CSS pixels is 1280×900 at 200% equivalent reflow, not browser chrome zoom.
    await page.setViewportSize({ width, height: width === 640 ? 450 : 900 });
    const { writes, reads, errors, saved } = await install(page, kind, locale);
    const entry = kind === 'ip' ? page.locator('#ip-investigation-entry') : page.locator('.job-investigation');
    await expect(entry.locator('form')).toHaveCount(0);
    await page.getByRole('button', { name: locale === 'ko' ? '다음 이력' : 'Next history', exact: true }).click();
    await page.getByRole('button', { name: new RegExp(saved.id) }).click();
    const run = page.getByRole('region', { name: title(kind, locale), exact: true });
    await expect(run).toBeVisible();
    await expect(run.locator('[data-investigation-claim]')).toHaveCount(3);
    const initial = await page.locator('*').count();
    expect(initial).toBeLessThanOrEqual(1200);
    expect(writes).toEqual([]);
    await page.screenshot({ path: testInfo.outputPath('overview.png'), fullPage: true });
    let peak = initial;
    const observe = async () => { peak = Math.max(peak, await page.locator('*').count()); expect(peak).toBeLessThanOrEqual(2500); };
    if (kind === 'job') {
      await expect(run).toContainText('NOT_ESTABLISHED');
      await expect(run).toContainText('UNKNOWN');
      const seen = new Set<string>();
      for (let index = 0; index < 4; index++) {
        const peers = run.getByRole('button', { name: new RegExp('^' + (locale === 'ko' ? '피어 상세 ' : 'Peer details ')) });
        await expect(peers).toHaveCount(8);
        for (const button of await peers.all()) {
          seen.add((await button.getAttribute('aria-label'))!.split(' ').at(-1)!);
          await button.click();
          const detail = run.getByRole('region', { name: locale === 'ko' ? '피어 평가 상세' : 'Peer assessment detail', exact: true });
          await expect(detail).toHaveCount(1);
          await observe();
        }
        if (index < 3) await run.getByRole('button', { name: locale === 'ko' ? '다음 피어' : 'Next peers', exact: true }).click();
      }
      expect([...seen].sort()).toEqual(savedNavigation.job.pool.entries.map(p => p.peer_id).sort());
      await run.getByRole('button', { name: new RegExp(locale === 'ko' ? '^주장 피어 보기 ' : '^View claim peer ') }).first().click();
      const assessment = savedNavigation.job.result!.kind === 'RESULT' ? savedNavigation.job.result!.assessments[0] : undefined;
      if (!assessment) throw new Error('Producer assessment missing');
      const detail = run.getByRole('region', { name: locale === 'ko' ? '피어 평가 상세' : 'Peer assessment detail', exact: true });
      for (const item of [...assessment.support, ...assessment.counterevidence]) await expect(detail.getByText(item.text, { exact: true })).toBeVisible();
      const button = detail.getByRole('button', { name: (locale === 'ko' ? '근거 ' : 'Evidence ') + assessment.evidence_quality[0].evidence_id, exact: true });
      await button.focus(); await page.keyboard.press('Enter');
      const evidence = page.getByRole(width <= 640 ? 'dialog' : 'region', { name: locale === 'ko' ? '선택 근거' : 'Selected evidence', exact: true });
      await expect(evidence).toBeVisible();
      await expect(evidence.getByRole('region', { name: locale === 'ko' ? '근거 상세' : 'Evidence details', exact: true })).toBeVisible();
      await observe();
      await page.screenshot({ path: testInfo.outputPath('selected.png'), fullPage: true });
      await page.keyboard.press('Escape'); await expect(evidence).toHaveCount(0); await expect(button).toBeFocused();
    } else {
      const result = savedNavigation.ip.result;
      if (!result || 'kind' in result) throw new Error('Producer result missing');
      for (const [key, name] of [['support', locale === 'ko' ? '패턴 가설' : 'Pattern hypotheses'], ['counterevidence', locale === 'ko' ? '반대 근거' : 'Counterevidence']] as const) {
        await run.getByRole('button', { name, exact: true }).click();
        const section = run.getByRole('region', { name, exact: true });
        const reached: string[] = [];
        for (let index = 0; index < 2; index++) {
          reached.push(...await section.locator('article > p').allTextContents());
          await observe();
          if (index === 0) await section.getByRole('button', { name: new RegExp(locale === 'ko' ? '^다음 ' + (key === 'support' ? '패턴 가설' : '반대 근거') : '^Next ' + key) }).click();
        }
        expect(reached).toEqual(result[key].map(claim => claim.text));
      }
      const facts = run.getByRole('button', { name: locale === 'ko' ? '관측 사실' : 'Observed facts', exact: true });
      const before = reads.length; await facts.focus(); await page.keyboard.press('ArrowRight'); expect(reads.length).toBe(before);
      await facts.click();
      const section = run.getByRole('region', { name: locale === 'ko' ? '관측 사실' : 'Observed facts', exact: true });
      const ref = result.facts.at(-1)!.ref;
      while (await section.getByRole('button', { name: ref, exact: true }).count() === 0) await section.getByRole('button', { name: locale === 'ko' ? '다음 관측 사실' : 'Next facts', exact: true }).click();
      const button = section.getByRole('button', { name: ref, exact: true });
      await button.focus(); await page.keyboard.press('Enter');
      const evidence = page.getByRole(width <= 640 ? 'dialog' : 'region', { name: locale === 'ko' ? '선택 근거' : 'Selected evidence', exact: true });
      await expect(evidence.getByText(ref, { exact: true })).toBeVisible();
      await observe();
      await page.screenshot({ path: testInfo.outputPath('selected.png'), fullPage: true });
      await page.keyboard.press('Escape'); await expect(evidence).toHaveCount(0); await expect(button).toBeFocused();
    }
    const geometry = await page.evaluate(() => ({ viewport: innerWidth, document: document.documentElement.scrollWidth }));
    expect(geometry.document).toBeLessThanOrEqual(geometry.viewport + 1);
    expect(writes).toEqual([]); expect(errors).toEqual([]);
    await testInfo.attach('budget-and-coverage', { contentType: 'application/json', body: JSON.stringify({ initial, peak, width, locale, kind, geometry, reads, writes, errors }) });
  });
}

for (const kind of ['ip', 'job'] as const) {
  test(`actual App ${kind} keeps exact admission and cancel owners across modal, history and purpose`, async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 900 });
    const { saved, errors } = await install(page, kind, 'en', true);
    const suffix = kind === 'ip' ? 'ai-investigations' : 'ai-job-investigations';
    const bodies: string[] = [], cancels: string[] = [];
    let acknowledge!: () => void, cancelAcknowledge!: () => void;
    const admission = new Promise<void>(done => { acknowledge = done; });
    const cancellation = new Promise<void>(done => { cancelAcknowledge = done; });
    let accepted: object;
    await page.route(`**/analysis-jobs/job/${suffix}`, async route => {
      if (route.request().method() !== 'POST') return route.fallback();
      bodies.push(route.request().postData()!);
      if (bodies.length === 1) return route.fulfill({ status: 503, body: '{}' });
      await admission;
      const request = route.request().postDataJSON();
      const base = kind === 'ip' ? savedNavigation.ipQueued : savedNavigation.jobQueued;
      accepted = { ...base, id: 'c'.repeat(64), request, ...(kind === 'ip' ? { language: request.language } : {}) };
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify(accepted) });
    });
    await page.route(`**/analysis-jobs/job/${suffix}/${'c'.repeat(64)}`, route => route.fulfill({ contentType: 'application/json', body: JSON.stringify(accepted) }));
    await page.route(`**/analysis-jobs/job/${suffix}/${'c'.repeat(64)}/cancel`, async route => {
      cancels.push(route.request().url()); await cancellation;
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ...accepted, status: 'CANCELLED', revision: 100 }) });
    });
    await page.route('**/source-preview', route => route.fulfill({ contentType: 'application/json', body: JSON.stringify(fixture('source_preview')) }));
    await page.getByRole('button', { name: 'Next history', exact: true }).click();
    await page.getByRole('button', { name: new RegExp(saved.id) }).click();
    await page.getByRole('button', { name: 'New investigation request', exact: true }).click();
    if (kind === 'ip') {
      await page.getByLabel('Target IP', { exact: true }).fill('2001:db8::1');
      await page.getByRole('button', { name: 'Preview scope', exact: true }).click();
      await page.getByRole('button', { name: 'Start investigation', exact: true }).click();
    } else await page.getByRole('button', { name: 'Start experimental investigation', exact: true }).click();
    const retryName = kind === 'ip' ? 'Retry captured request' : 'Retry exact request';
    await expect(page.getByRole('button', { name: retryName, exact: true })).toBeEnabled();
    await page.getByRole('button', { name: 'Results & evidence', exact: true }).click();
    await expect(page.getByText(/Admission is unconfirmed/)).toBeVisible();
    await page.getByRole('button', { name: 'AI investigation', exact: true }).click();
    await page.getByRole('button', { name: retryName, exact: true }).click();
    await expect.poll(() => bodies.length).toBe(2);
    expect(bodies[1]).toBe(bodies[0]);
    if (kind === 'job') expect(JSON.parse(bodies[0]).expected_source_sha256).toBeNull();
    await page.getByRole('button', { name: new RegExp(saved.id) }).click();
    const run = page.getByRole('region', { name: title(kind, 'en'), exact: true });
    if (kind === 'ip') {
      await run.getByRole('button', { name: 'Issued evidence', exact: true }).click();
      await run.getByRole('button', { name: /^Evidence / }).first().click();
    } else {
      await run.getByRole('button', { name: 'Peer details ' + savedNavigation.job.selection.peer_ids[0], exact: true }).click();
      await run.getByRole('button', { name: /^Evidence / }).first().click();
    }
    const modal = page.getByRole('dialog', { name: 'Selected evidence', exact: true });
    await expect(modal).toBeVisible();
    await expect(modal.getByText(/Awaiting admission acknowledgment/)).toBeVisible();
    await page.keyboard.press('Escape');
    await page.getByRole('button', { name: 'Results & evidence', exact: true }).click();
    await expect(page.getByText('Awaiting admission acknowledgment', { exact: true })).toBeVisible();
    acknowledge();
    await expect(page.getByRole('button', { name: /Return to active investigation/ })).toBeVisible();
    await page.getByRole('button', { name: 'AI investigation', exact: true }).click();
    await expect(page.getByRole('region', { name: title(kind, 'en'), exact: true })).toContainText(saved.id);
    await page.getByRole('button', { name: /Return to active investigation/ }).click();
    await page.getByRole('button', { name: kind === 'ip' ? 'Cancel investigation' : 'Request cancellation of this run', exact: true }).click();
    if (kind === 'ip') await page.getByRole('button', { name: 'Confirm cancel this run', exact: true }).click();
    await expect.poll(() => cancels.length).toBe(1);
    await page.getByRole('button', { name: 'Results & evidence', exact: true }).click();
    await expect(page.getByText('Cancellation acknowledgment pending', { exact: true })).toBeVisible();
    await expect(page.getByRole('region', { name: title(kind, 'en'), exact: true })).toHaveCount(0);
    await expect(page.locator('.investigation-form,.job-investigation form')).toHaveCount(0);
    cancelAcknowledge();
    await expect(page.getByRole('status').filter({ hasText: 'CANCELLED' })).toBeVisible();
    expect(bodies).toHaveLength(2); expect(cancels).toHaveLength(1); expect(errors).toEqual([]);
  });
}

for (const kind of ['ip', 'job'] as const) {
  test(`L3 actual App ${kind} cancellation receipts update inside one open narrow evidence modal`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 390, height: 900 });
    const { saved, errors } = await install(page, kind, 'en');
    const suffix = kind === 'ip' ? 'ai-investigations' : 'ai-job-investigations';
    const queued = { ...(kind === 'ip' ? savedNavigation.ipQueued : savedNavigation.jobQueued), id: 'c'.repeat(64) };
    let failed!: () => void, settled!: () => void;
    const failure = new Promise<void>(done => { failed = done; });
    const settlement = new Promise<void>(done => { settled = done; });
    const posts: string[] = [];
    await page.route(`**/analysis-jobs/job/${suffix}?*`, route => route.fulfill({ contentType: 'application/json', body: JSON.stringify(new URL(route.request().url()).searchParams.has('after') ? { items: [saved], next_cursor: null } : { items: [queued], next_cursor: queued.id }) }));
    await page.route(`**/analysis-jobs/job/${suffix}/${queued.id}`, route => route.fulfill({ contentType: 'application/json', body: JSON.stringify(queued) }));
    await page.route(`**/analysis-jobs/job/${suffix}/${queued.id}/cancel`, async route => {
      posts.push(route.request().url());
      if (posts.length === 1) { await failure; return route.fulfill({ status: 503, body: '{}' }); }
      await settlement;
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ...queued, status: 'CANCELLED', revision: queued.revision + 1 }) });
    });
    await page.getByRole('button', { name: kind === 'ip' ? 'Retry history read' : 'First history / Refresh', exact: true }).click();
    await page.getByRole('button', { name: new RegExp(queued.id) }).click();
    await page.getByRole('button', { name: kind === 'ip' ? 'Cancel investigation' : 'Request cancellation of this run', exact: true }).click();
    if (kind === 'ip') await page.getByRole('button', { name: 'Confirm cancel this run', exact: true }).click();
    await expect.poll(() => posts.length).toBe(1);
    await page.getByRole('button', { name: 'Next history', exact: true }).click();
    await page.getByRole('button', { name: new RegExp(saved.id) }).click();
    const run = page.getByRole('region', { name: title(kind, 'en'), exact: true });
    if (kind === 'ip') await run.getByRole('button', { name: 'Issued evidence', exact: true }).click();
    else await run.getByRole('button', { name: 'Peer details ' + savedNavigation.job.selection.peer_ids[0], exact: true }).click();
    await run.getByRole('button', { name: /^Evidence / }).first().click();
    const modal = page.getByRole('dialog', { name: 'Selected evidence', exact: true });
    const heading = modal.getByRole('heading', { name: 'Selected evidence', exact: true });
    await expect(modal.getByText('Cancellation acknowledgment pending', { exact: true })).toBeVisible();
    await expect(heading).toBeFocused();
    await page.screenshot({ path: testInfo.outputPath('cancel-pending.png') });
    failed();
    await expect(modal.getByText(/cancellation unconfirmed/)).toBeVisible();
    await expect(heading).toBeFocused();
    await page.screenshot({ path: testInfo.outputPath('cancel-unconfirmed.png') });
    await modal.getByRole('button', { name: 'Retry cancellation', exact: true }).click();
    await expect(modal.getByText('Cancellation acknowledgment pending', { exact: true })).toBeVisible();
    await expect.poll(() => posts.length).toBe(2);
    settled();
    await expect(modal.getByText(/CANCELLED.*does not prove worker release/)).toBeVisible();
    await expect(modal.getByText(/cancellation unconfirmed/)).toHaveCount(0);
    await page.screenshot({ path: testInfo.outputPath('cancel-settled.png') });
    expect(posts[1]).toBe(posts[0]);
    expect(errors).toEqual([]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
    await page.keyboard.press('Escape');
    await expect(modal).toHaveCount(0);
    await page.getByRole('button', { name: /Return to active investigation/ }).click();
    await page.getByRole('button', { name: 'Acknowledge retained outcome', exact: true }).click();
    await expect(page.getByRole('button', { name: /Return to active investigation/ })).toHaveCount(0);
  });
}
