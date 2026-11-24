import { withLegacyAuthentication } from './auth-fixture';
import { expect, test, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { savedNavigation } from '../tests/investigationSavedNavigationFixtures';
import { fixture } from '../tests/investigationFixtures';
import { producer } from '../tests/jobInvestigationFixtures';

type Locale = 'ko' | 'en';
const text = (locale: Locale, en: string, ko: string) => locale === 'ko' ? ko : en;
const python = process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python');
const network = JSON.parse(execFileSync(python, ['tests/network_report_fixture.py', '--maximum'], { encoding: 'utf8', maxBuffer: 20000000 }));
const networkJob = JSON.parse(execFileSync(python, ['tests/network_public_job_fixture.py'], { input: JSON.stringify(network.many), encoding: 'utf8', maxBuffer: 20000000 }));
const ddosJob = JSON.parse(readFileSync('../controller/tests/fixtures/pcap_attack_guidance/positive.job.json', 'utf8'));
// Same public C2 source fixture used by investigation-saved-navigation.spec.ts.
const c2Job = {
      id: 'job', dataset_id: 'dataset', name: 'Saved result with long source metadata '.repeat(5),
      description: 'Analyst note retained separately from investigation results. '.repeat(8),
      status: 'COMPLETED', source_type: 'PCAP_UPLOAD', analysis: { module: 'c2' },
      processing: { phase: 'COMPLETED', phase_started_at: '2026-11-15T00:01:02Z' },
      source: { filename: 'saved-investigation-long-source.pcap', size_bytes: 65536, captured_packet_count: 2000, parsed_packet_count: 1000, skipped_packet_count: 1000, sha256: 'a'.repeat(64) },
      warnings: ['Fixture coverage limitation: some packets were not parsed.'], packet_count: 1000, flow_count: 61, candidate_count: 1,
      start_time: '2026-11-15T00:00:00Z', end_time: '2026-11-15T00:01:00Z',
    };
const ipResult = savedNavigation.ip.result;
const jobResult = savedNavigation.job.result;
if (!ipResult || 'kind' in ipResult || !jobResult || jobResult.kind !== 'RESULT') throw new Error('Producer model results missing');
const ipProse = ipResult.support[0].text;
const jobProse = jobResult.assessments[0].support[0].text;

async function switchLocale(page: Page, from: Locale, to: Locale, keyboard: boolean) {
  // The root chooser precedes the independently scoped normal-reference form.
  const control = page.getByRole('combobox', { name: text(from, 'Report language', '보고서 언어'), exact: true }).first();
  await expect(control).toHaveValue(from);
  const original = await control.elementHandle();
  await control.focus();
  if (keyboard) {
    await page.keyboard.press(to === 'en' ? 'ArrowDown' : 'ArrowUp');
    await page.keyboard.press('Enter');
  } else await control.selectOption(to);
  const changed = page.getByRole('combobox', { name: text(to, 'Report language', '보고서 언어'), exact: true }).first();
  await expect(changed).toHaveValue(to);
  await expect(changed).toBeFocused();
  expect(await changed.evaluate((node, prior) => node === prior, original)).toBe(true);
  await expect(changed.locator('option')).toHaveText(['한국어', 'English']);
  await original?.dispose();
}

for (const kind of ['ip', 'job', 'network', 'ddos'] as const) for (const width of [1280, 390]) for (const locale of ['ko', 'en'] as const) {
  test(`localized chooser preserves ${kind} saved prose and captured admission ${width} ${locale}`, async ({ page }, info) => {
    const other: Locale = locale === 'ko' ? 'en' : 'ko';
    const investigation = kind === 'ip' || kind === 'job';
    const job = kind === 'network' ? networkJob : kind === 'ddos' ? ddosJob : c2Job;
    const analysisKind = kind === 'network' ? 'NETWORK_ANOMALY' : 'DDOS_ATTACK';
    // Reuse the existing saved interpretation transport fixture; deterministic reports are producer-backed.
    const findingId = kind === 'network' ? network.many.issues[19].id : job.ddos_attack?.findings[0].id;
    const older = kind === 'network' ? { ...network.run, id: 'older', analysis_job_id: job.id, dataset_id: job.dataset_id, network_interpretation: { ...network.run.network_interpretation, summary: 'Saved English hypothesis. Not a confirmed diagnosis.' } } : {
      id: 'older', analysis_job_id: job.id, dataset_id: job.dataset_id, analysis_kind: 'DDOS_ATTACK', status: 'COMPLETED', language: 'en',
      ddos_interpretation: { schema_version: 'ddos-interpretation-v1', kind: 'MODEL_INTERPRETATION', language: 'en', summary: 'Saved English hypothesis. Not a confirmed diagnosis.', risk_context: Array.from({ length: 10 }, (_, i) => ({ interpretation: `Retained risk hypothesis ${i}.`, finding_ids: [findingId], uncertainty: 'Service impact is not measured.' })), prioritized_checks: [{ priority: 'HIGH', check: 'Compare service logs.', finding_ids: [findingId] }], response_considerations: [{ consideration: 'Review response with an analyst.', finding_ids: [findingId], requires_human_approval: true }], limitations: ['No attribution or measured impact.'] },
    };
    const saved = kind === 'ip' ? savedNavigation.ip : kind === 'job' ? savedNavigation.job : older;
    const savedBytes = JSON.stringify(saved);
    const prose = kind === 'ip' ? ipProse : kind === 'job' ? jobProse : 'Saved English hypothesis. Not a confirmed diagnosis.';
    const proseLanguage = kind === 'ip' ? savedNavigation.ip.language : kind === 'job' ? savedNavigation.job.request.language : 'en';
    const suffix = kind === 'ip' ? 'ai-investigations' : kind === 'job' ? 'ai-job-investigations' : 'ai-runs';
    const admissionPath = `/api/v1/analysis-jobs/${job.id}/${suffix}`;
    const posts: { path: string; body: string }[] = [], errors: string[] = [];
    const previews: string[] = [];
    const releases: (() => void)[] = [];
    let accepted: unknown;
    await page.setViewportSize({ width, height: 900 });
    await page.addInitScript(value => { localStorage.setItem('c2hunter-token', 'localized-fixture'); localStorage.setItem('c2hunter-report-language', value); }, locale);
    page.on('pageerror', error => errors.push(error.message));
    await page.route('**/api/v1/**', withLegacyAuthentication(async route => {
      const request = route.request(), url = new URL(request.url()), path = url.pathname;
      if (request.method() === 'POST' && path === admissionPath + '/source-preview') {
        expect(kind).toBe('ip');
        previews.push(request.postData()!);
        return route.fulfill({ contentType: 'application/json', body: JSON.stringify(fixture('source_preview')) });
      }
      if (request.method() !== 'GET') {
        posts.push({ path, body: request.postData() ?? '' });
        expect(path).toBe(admissionPath);
        const attempt = posts.length;
        await new Promise<void>(done => { releases.push(done); });
        if (attempt === 1) return route.fulfill({ status: 503, body: '{}' });
        const captured = request.postDataJSON();
        accepted = investigation ? { ...(kind === 'ip' ? savedNavigation.ipQueued : savedNavigation.jobQueued), id: 'c'.repeat(64), request: captured, ...(kind === 'ip' ? { language: captured.language } : {}) } : { id: 'admitted', analysis_job_id: job.id, dataset_id: job.dataset_id, analysis_kind: analysisKind, language: captured.language, status: 'ANALYZING' };
        return route.fulfill({ contentType: 'application/json', body: JSON.stringify(accepted) });
      }
      let body: unknown = { items: [], total: 0 };
      if (path === `/api/v1/analysis-jobs/${job.id}`) body = job;
      else if (path.endsWith('/candidates')) body = { items: [{ id: 'saved-candidate', candidate_ip: '2001:db8::1', score: 42, severity: 'MEDIUM' }], page: 1, page_size: Number(url.searchParams.get('page_size') ?? 25), total: 1 };
      else if (path.endsWith('/capabilities')) body = kind === 'ip' ? fixture('capabilities') : JSON.parse(producer.fixtures.capabilities);
      else if (path.endsWith('/ai-capabilities')) body = { available: true, network_interpretation: true, ddos_interpretation: true, remote: false };
      else if (path === admissionPath) body = investigation ? { items: [saved], next_cursor: null } : { items: [older], current_page: 1, page_size: 50, total: 1 };
      else if (path.endsWith('/older')) body = older;
      else if (path.endsWith('/admitted') || path.endsWith('/' + 'c'.repeat(64))) body = accepted;
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify(body) });
    }));
    const button = (en: string, ko: string, language = locale) => page.getByRole('button', { name: text(language, en, ko), exact: true });
    const savedView = (language: Locale) => page.getByRole('region', { name: text(language, kind === 'ip' ? 'Selected investigation' : 'Saved job investigation', kind === 'ip' ? '선택 조사' : '저장된 작업 조사'), exact: true });
    const assertProse = async (language: Locale) => {
      const view = investigation ? savedView(language) : page;
      await expect(view.getByText(prose, { exact: true }).first()).toBeVisible();
      await expect(view.getByText(prose, { exact: true }).first()).toHaveAttribute('lang', proseLanguage);
      expect(JSON.stringify(saved)).toBe(savedBytes);
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
      expect(await page.evaluate(() => document.body.scrollWidth)).toBeLessThanOrEqual(width);
    };
    try {
      await page.goto(`/analyses/${job.id}`);
      if (investigation) {
        await button('AI investigation', 'AI 조사').click();
        await button(kind === 'ip' ? 'Open IP investigation' : 'Open experimental investigation', kind === 'ip' ? 'IP 조사 열기' : '실험적 조사 열기').click();
        await page.getByRole('button', { name: new RegExp(saved.id) }).click();
      } else {
        await button(kind === 'network' ? 'Open AI interpretation' : 'Open DDoS AI interpretation', kind === 'network' ? 'AI 해석 열기' : 'DDoS AI 해석 열기').click();
        await button('View saved run older', '저장 실행 보기 older').click();
      }
      await assertProse(locale);
      await switchLocale(page, locale, other, true);
      await assertProse(other);
      expect(posts).toEqual([]);
      await page.screenshot({ path: info.outputPath('saved-switched.png') });
      await switchLocale(page, other, locale, false);
      await assertProse(locale);
      expect(posts).toEqual([]);
      expect(previews).toEqual([]);
      await button(investigation ? 'New investigation request' : 'New AI interpretation', investigation ? '새 조사 요청' : '새 AI 해석').click();
      if (investigation) {
        // The explicitly chosen new-request language is not the current UI locale.
        await page.getByRole('combobox', { name: kind === 'ip' ? text(locale, 'Language', '언어') : text(locale, 'New request report language', '새 요청 보고서 언어'), exact: true }).selectOption(other);
        if (kind === 'ip') {
          await page.getByLabel(text(locale, 'Target IP', '대상 IP'), { exact: true }).fill('2001:db8::1');
          await button('Preview scope', '범위 미리보기').click();
        }
      }
      expect(posts).toEqual([]);
      await button(kind === 'ip' ? 'Start investigation' : kind === 'job' ? 'Start experimental investigation' : kind === 'network' ? 'AI interpretation' : 'Run DDoS AI interpretation', kind === 'ip' ? '조사 시작' : kind === 'job' ? '실험적 조사 시작' : kind === 'network' ? 'AI 해석' : 'DDoS AI 해석 실행').click();
      await expect.poll(() => releases.length).toBe(1);
      if (investigation) await page.getByRole('button', { name: new RegExp(saved.id) }).click();
      const captured = JSON.parse(posts[0].body);
      expect(captured.language).toBe(investigation ? other : locale);
      expect(captured.idempotency_key).toEqual(expect.any(String));
      expect(captured.idempotency_key.length).toBeGreaterThan(0);
      await switchLocale(page, locale, other, true);
      await expect(page.getByText(text(other, investigation ? 'Awaiting admission acknowledgment' : 'AI request pending — admission not yet confirmed.', investigation ? '수락 확인 중' : 'AI 요청 대기 중 — 접수는 아직 확인되지 않았습니다.'), { exact: true }).first()).toBeVisible();
      expect(posts).toHaveLength(1);
      await assertProse(other);
      await page.screenshot({ path: info.outputPath('pending-switched.png') });
      releases[0]();
      const retry = button(kind === 'ip' ? 'Retry captured request' : kind === 'job' ? 'Retry exact request' : 'Retry exact AI request', kind === 'ip' ? '동일 요청 재시도' : kind === 'job' ? '정확한 요청 재시도' : '동일한 AI 요청 재시도', other);
      await expect(retry).toBeEnabled();
      await switchLocale(page, other, locale, false);
      expect(posts).toHaveLength(1);
      const retryOriginal = button(kind === 'ip' ? 'Retry captured request' : kind === 'job' ? 'Retry exact request' : 'Retry exact AI request', kind === 'ip' ? '동일 요청 재시도' : kind === 'job' ? '정확한 요청 재시도' : '동일한 AI 요청 재시도');
      await retryOriginal.click();
      await expect.poll(() => releases.length).toBe(2);
      expect(posts[1]).toEqual(posts[0]);
      if (investigation) await page.getByRole('button', { name: new RegExp(saved.id) }).click();
      await switchLocale(page, locale, other, false);
      expect(posts).toHaveLength(2);
      releases[1]();
      if (investigation) await expect(button('Return to active investigation ' + 'c'.repeat(64), '활성 조사로 돌아가기 ' + 'c'.repeat(64), other).first()).toBeVisible();
      else await expect(button('Cancel AI run', 'AI 실행 취소', other)).toBeVisible();
      expect(posts).toHaveLength(2);
      await assertProse(other);
      expect(previews).toHaveLength(kind === 'ip' ? 1 : 0);
      expect(errors).toEqual([]);
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
      await info.attach('captured-admission', { body: JSON.stringify({ kind, width, locale, posts, previews, savedLanguage: proseLanguage, errors }), contentType: 'application/json' });
      await info.attach('localized-accessibility', { body: await page.locator('main').ariaSnapshot(), contentType: 'text/plain' });
    } finally { releases.forEach(release => release()); }
  });
}
