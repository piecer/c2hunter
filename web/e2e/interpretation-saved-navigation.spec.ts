import { expect, test } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// Producer reports/public jobs; AI prose and HTTP scheduling are transport fixtures.
const python = process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python');
const network = JSON.parse(execFileSync(python, ['tests/network_report_fixture.py', '--maximum'], { encoding: 'utf8', maxBuffer: 20000000 }));
const networkJob = JSON.parse(execFileSync(python, ['tests/network_public_job_fixture.py'], { input: JSON.stringify(network.many), encoding: 'utf8', maxBuffer: 20000000 }));
const ddosJob = JSON.parse(readFileSync('../controller/tests/fixtures/pcap_attack_guidance/positive.job.json', 'utf8'));
for (const width of [1280, 390]) for (const language of ['en', 'ko']) for (const kind of ['network', 'ddos']) {
  test(`saved ${kind} interpretation navigation ${width}px ${language}`, async ({ page }, info) => {
    const ko = language === 'ko', isNetwork = kind === 'network';
    const t = (en: string, kor: string) => ko ? kor : en;
    await page.setViewportSize({ width, height: 900 });
    await page.addInitScript(lang => { localStorage.setItem('c2hunter-token', 'saved-fixture'); localStorage.setItem('c2hunter-report-language', lang); }, language);
    const job = isNetwork ? networkJob : { ...ddosJob, name: 'Long retained DDoS capture metadata '.repeat(12), description: 'Retained analyst qualification. '.repeat(30) };
    const findingId = isNetwork ? network.many.issues[19].id : job.ddos_attack.findings[0].id;
    const older = isNetwork ? { ...network.run, id: 'older', analysis_job_id: job.id, dataset_id: job.dataset_id, network_interpretation: { ...network.run.network_interpretation, summary: 'Saved English hypothesis. Not a confirmed diagnosis.' } } : {
      id: 'older', analysis_job_id: job.id, dataset_id: job.dataset_id, analysis_kind: 'DDOS_ATTACK', status: 'COMPLETED', language: 'en',
      ddos_interpretation: { schema_version: 'ddos-interpretation-v1', kind: 'MODEL_INTERPRETATION', language: 'en', summary: 'Saved English hypothesis. Not a confirmed diagnosis.', risk_context: Array.from({ length: 10 }, (_, i) => ({ interpretation: `Retained risk hypothesis ${i}.`, finding_ids: [findingId], uncertainty: 'Service impact is not measured.' })), prioritized_checks: [{ priority: 'HIGH', check: 'Compare service logs.', finding_ids: [findingId] }], response_considerations: [{ consideration: 'Review response with an analyst.', finding_ids: [findingId], requires_human_approval: true }], limitations: ['No attribution or measured impact.'] },
    };
    const latest = { ...older, id: 'latest', status: 'ANALYZING', network_interpretation: undefined, ddos_interpretation: undefined };
    const errors: string[] = [], writes: string[] = [], reads: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.route('**/api/v1/**', async route => {
      const request = route.request(), url = new URL(request.url()), path = url.pathname.replace('/api/v1', '');
      if (request.method() !== 'GET') writes.push(path); else reads.push(path + url.search);
      let body: unknown = { items: [] };
      if (path === `/analysis-jobs/${job.id}`) body = job;
      else if (path === '/ai-capabilities') body = { available: false, network_interpretation: false, ddos_interpretation: false, reason: 'Read-only saved fixture' };
      else if (path === `/analysis-jobs/${job.id}/ai-runs`) {
        const current_page = Number(url.searchParams.get('page') ?? 1);
        const others = Array.from({ length: 50 }, (_, i) => ({ id: `other-${current_page}-${i}`, analysis_kind: 'C2', status: 'COMPLETED', language: 'en' }));
        body = { items: current_page === 3 ? [older] : current_page === 2 ? others : [latest, ...others.slice(0, 49)], current_page, page_size: 50, total: 101 };
      }
      else if (path === '/ai-runs/latest') body = latest;
      else if (path === '/ai-runs/older') body = older;
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify(body) });
    });
    const measurements: unknown[] = [];
    const measure = async (phase: string, ceiling = 2500) => {
      const geometry = await page.evaluate(() => ({ nodes: document.querySelectorAll('*').length, body: document.body.scrollWidth, document: document.documentElement.scrollWidth }));
      expect(geometry.nodes).toBeLessThanOrEqual(ceiling); expect(geometry.body).toBeLessThanOrEqual(width); expect(geometry.document).toBeLessThanOrEqual(width); measurements.push({ phase, ...geometry });
    };
    await page.goto(`/analyses/${job.id}`);
    const openName = isNetwork ? t('Open AI interpretation', 'AI 해석 열기') : t('Open DDoS AI interpretation', 'DDoS AI 해석 열기');
    await expect(page.getByRole('button', { name: openName, exact: true })).toBeVisible();
    await measure('initial', 1200);
    await page.screenshot({ path: info.outputPath('overview.png') });
    await page.getByRole('button', { name: openName, exact: true }).click();
    const submitName = isNetwork ? t('AI interpretation', 'AI 해석') : t('Run DDoS AI interpretation', 'DDoS AI 해석 실행');
    await expect(page.getByRole('button', { name: submitName, exact: true })).toHaveCount(0);
    await page.getByRole('button', { name: t('Next saved runs', '다음 저장 실행') }).click();
    await expect(page.getByText(t('No matching runs on this page.', '이 페이지에 해당 실행이 없습니다.'))).toBeVisible();
    await page.getByRole('button', { name: t('Next saved runs', '다음 저장 실행') }).click();
    await page.getByRole('button', { name: t('View saved run older', '저장 실행 보기 older') }).click();
    await expect(page.getByText('Saved English hypothesis. Not a confirmed diagnosis.')).toHaveAttribute('lang', 'en');
    await expect(page.getByRole('status', { name: t('Latest AI run', '최신 AI 실행') })).toContainText(isNetwork ? t('Analyzing', '해석 중') : t('ANALYZING', '해석 중'));
    await measure('selected overview', isNetwork ? 499 : 2500);
    await page.getByRole('button', { name: t('View full AI text', 'AI 원문 전체 보기') }).click();
    const article = page.getByRole('article', { name: isNetwork ? t('Full AI interpretation', 'AI 해석 전체 원문') : t('Full DDoS AI interpretation', 'DDoS AI 해석 전체 원문') });
    await expect(article).toBeVisible();
    await measure('selected full', isNetwork ? 499 : 2500);
    await page.screenshot({ path: info.outputPath('selected.png') });
    if (isNetwork) await article.getByRole('button', { name: findingId, exact: true }).first().click();
    else {
      await expect(article.getByRole('button', { name: findingId, exact: true }).first()).toBeDisabled();
      await article.getByRole('button', { name: `${t('Inspect current report, not verified saved evidence:', '현재 보고서 조사 — 저장 근거 검증 아님:')} ${findingId}`, exact: true }).first().click();
    }
    const evidence = page.getByRole('region', { name: isNetwork ? t('Representative flow evidence', '대표 흐름 증거') : t('DDoS finding evidence', 'DDoS 발견 근거'), exact: true });
    await expect(evidence).toBeVisible();
    await measure('citation');
    if (isNetwork) {
      await expect(evidence).toBeFocused();
      await page.getByRole('button', { name: /Hide representative evidence|숨기기 대표 증거/ }).click();
      await expect(page.locator('#overall-network-heading')).toBeFocused();
    } else {
      const surface = page.getByRole(width < 600 ? 'dialog' : 'region', { name: t('DDoS detail', 'DDoS 상세'), exact: true });
      await expect(surface).toBeVisible();
      if (width < 600) await expect(surface).toHaveAttribute('aria-modal', 'true'); else await expect(surface).not.toHaveAttribute('aria-modal', 'true');
      await surface.getByRole('button', { name: t('Close detail', '상세 닫기') }).click();
      await expect(page.locator('#ddos-heading')).toBeFocused();
    }
    await page.getByRole('button', { name: isNetwork ? t('Return to cited AI claim', '인용한 AI 주장으로 돌아가기') : t('Return to saved AI claim', '저장된 AI 주장으로 돌아가기'), exact: true }).click();
    await expect(article).toBeVisible();
    await page.getByRole('button', { name: t('New AI interpretation', '새 AI 해석') }).click();
    await expect(page.getByRole('button', { name: submitName, exact: true })).toBeDisabled();
    // The primary report locale is in this slice; the separate retained
    // normal-reference form's chooser is part of parent stage4C convergence.
    await page.getByRole('combobox', { name: /^(보고서 언어|Report language)$/ }).first().selectOption(ko ? 'en' : 'ko');
    await expect(page.getByText('Saved English hypothesis. Not a confirmed diagnosis.')).toHaveAttribute('lang', 'en');
    expect(reads).toContain(`/analysis-jobs/${job.id}/ai-runs?page=3&page_size=50`);
    expect(writes).toEqual([]); expect(errors).toEqual([]);
    await info.attach('mounted-geometry', { body: JSON.stringify(measurements), contentType: 'application/json' });
    await info.attach('accessibility', { body: await page.locator('main').ariaSnapshot(), contentType: 'text/plain' });
  });
}
