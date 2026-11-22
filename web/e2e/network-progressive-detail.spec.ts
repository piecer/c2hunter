import { expect, test, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { factLabel } from '../src/reportTranslations';
import type { PatternIssue } from '../src/NetworkPatternReport';

// Actual producer evidence, intercepted transport; no controller/model execution.
const python = process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python');
const maximum = JSON.parse(execFileSync(python, ['tests/network_report_fixture.py', '--maximum'], { encoding: 'utf8', maxBuffer: 20000000 }));
const publicJob = JSON.parse(execFileSync(python, ['tests/network_public_job_fixture.py'], { input: JSON.stringify(maximum.many), encoding: 'utf8', maxBuffer: 20000000 }));
const limited = JSON.parse(execFileSync(python, ['tests/network_report_fixture.py', '--limited'], { encoding: 'utf8' }));
const limitedJob = JSON.parse(execFileSync(python, ['tests/network_public_job_fixture.py'], { input: JSON.stringify(limited), encoding: 'utf8', maxBuffer: 20000000 }));
const numeric = JSON.parse(execFileSync(python, ['tests/network_numeric_fixture.py'], { encoding: 'utf8', maxBuffer: 20000000 }));
async function setup(page: Page, width: number, language: string, fullJob = publicJob) {
  await page.setViewportSize({ width, height: 900 });
  await page.addInitScript(language => {
    localStorage.setItem('c2hunter-token', 'progressive-fixture');
    localStorage.setItem('c2hunter-report-language', language);
  }, language);
  const requests: string[] = [], errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  const jobs = ['progressive-a', 'progressive-b'].map(id => ({ id, name: id, dataset_id: 'progressive-dataset', status: 'COMPLETED', source_type: 'PCAP_UPLOAD', mode: 'PCAP_UPLOAD', description: 'Source and processing metadata remain available. '.repeat(20), analysis: { module: 'network_anomaly' }, network_anomaly: maximum.many }));
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '');
    requests.push(`${route.request().method()} ${path}`);
    let body: unknown = { items: [] };
    if (path === '/analysis-jobs') body = { items: [...jobs, { ...numeric.job, name: 'Numeric source' }] };
    else if (path === '/analysis-jobs/full-envelope-network-job') body = fullJob;
    else if (path === '/ai-capabilities') body = { available: true, network_interpretation: true, remote: false };
    else if (path === '/analysis-jobs/numeric-job') body = { ...numeric.job, name: 'Numeric source', mode: 'PCAP_UPLOAD', source_type: 'PCAP_UPLOAD' };
    else if (path === '/analysis-jobs/numeric-job/ai-runs') body = { items: [numeric.run] };
    else if (path === `/ai-runs/${numeric.run.id}`) body = numeric.run;
    else body = jobs.find(job => path === `/analysis-jobs/${job.id}`) ?? body;
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify(body) });
  });
  return { requests, errors };
}
test('Network language selector also updates job work information', async ({ page }) => {
  await setup(page, 390, 'en');
  await page.goto('/analyses/full-envelope-network-job');
  await page.getByRole('combobox', { name: /^(보고서 언어|Report language)$/ }).selectOption('ko');
  await page.getByRole('button', { name: '작업 정보', exact: true }).click();
  await expect(page.getByRole('region', { name: '작업 정보', exact: true })).toContainText(publicJob.description);
  await page.getByRole('combobox', { name: /^(보고서 언어|Report language)$/ }).selectOption('en');
  await expect(page.getByRole('region', { name: 'Work information', exact: true })).toContainText(publicJob.name);
});
for (const width of [1280, 390]) for (const language of ['en', 'ko'] as const) {
  const ko = language === 'ko';
  for (const [scenario, job] of [['maximum', publicJob], ['limited', limitedJob]] as const) test(`full public job ${scenario} first fold ${width}px ${language}`, async ({ page }, info) => {
    const { requests, errors } = await setup(page, width, language, job);
    await page.goto('/analyses/full-envelope-network-job');
    const glance = page.getByRole('region', { name: ko ? '한눈에 보기' : 'At a glance', exact: true });
    await expect(glance).toBeVisible();
    await page.screenshot({ path: info.outputPath('full-envelope-overview.png'), fullPage: true });
    const bounds = [];
    const limitations = scenario === 'maximum' ? [glance.getByText(ko ? /보고서 일부 생략:/ : /Report truncated:/)] : [glance.getByText(ko ? /분석 범위가 불완전하거나/ : /Incomplete or unknown coverage/), glance.getByText(ko ? /수치는 하한값이며/ : /Counts are lower bounds/)];
    for (const locator of [glance.getByTestId('network-verdict'), ...limitations, glance.getByRole('region', { name: ko ? '다음 행동' : 'Next action' })]) {
      const box = await locator.boundingBox(); bounds.push(box);
      expect(box).not.toBeNull(); expect(box!.y).toBeGreaterThanOrEqual(0);
      expect(box!.y + box!.height).toBeLessThanOrEqual(900);
    }
    expect(await page.locator('*').count()).toBeLessThan(500);
    await page.getByRole('button', { name: ko ? '작업 정보' : 'Work information', exact: true }).click();
    for (const value of [publicJob.name, publicJob.description, publicJob.id, publicJob.dataset_id, ...publicJob.warnings]) await expect(page.getByRole('region', { name: ko ? '작업 정보' : 'Work information', exact: true }).getByText(value, { exact: true })).toBeVisible();
    for (const value of [publicJob.source.filename, publicJob.source.sha256]) await expect(page.getByText(value, { exact: true })).toBeVisible();
    await expect(page.getByRole('region', { name: 'PCAP 분석 처리 단계' })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await info.attach('full-envelope-bounds', { body: JSON.stringify(bounds), contentType: 'application/json' });
    expect(errors).toEqual([]); expect(requests.every(r => r.startsWith('GET '))).toBe(true);
  });
  test(`responsive example keyboard ownership ${width}px ${language}`, async ({ page }, info) => {
    const { requests, errors } = await setup(page, width, language);
    await page.goto('/analyses/full-envelope-network-job');
    await page.getByRole('button', { name: /Inspect evidence|근거 확인/ }).first().click();
    const selector = page.getByLabel(ko ? '대표 예시' : 'Representative example', { exact: true });
    await selector.selectOption('0');
    const name = ko ? '선택한 대표 예시' : 'Selected representative example';
    const panel = page.getByRole(width < 1200 ? 'dialog' : 'region', { name, exact: true });
    await expect(panel).toBeVisible();
    await expect(panel.getByRole('heading', { name, exact: true })).toBeFocused();
    if (width < 1200) await expect(panel).toHaveAttribute('aria-modal', 'true');
    else await expect(panel).not.toHaveAttribute('aria-modal');
    await expect(panel.getByLabel(ko ? '대표 예시' : 'Representative example', { exact: true })).toHaveValue('0');
    await panel.getByRole('button', { name: ko ? '전체 측정값' : 'Full measurements', exact: true }).click();
    await page.screenshot({ path: info.outputPath('full-envelope-selected-detail.png'), fullPage: true });
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog', { name })).toHaveCount(0);
    await expect(selector).toBeFocused();
    await expect(page.getByRole('region', { name: ko ? '보조 측정값' : 'Supporting measurements', exact: true })).toHaveCount(0);
    // 200% desktop reflow equivalent: 1280x900 -> 640x450 CSS pixels.
    // This is viewport emulation, NOT a DPR-only or native browser zoom claim.
    await selector.selectOption('9');
    await page.setViewportSize({ width: 1280, height: 900 });
    const desktop = page.getByRole('region', { name, exact: true });
    await expect(desktop).toBeVisible();
    const back = page.getByRole('link', { name: 'Back to analysis history' });
    await back.focus(); await expect(back).toBeFocused();
    await expect(page.locator('[inert]')).toHaveCount(0);
    await page.setViewportSize({ width: 640, height: 450 });
    const modal = page.getByRole('dialog', { name, exact: true });
    await expect(modal).toHaveAttribute('aria-modal', 'true');
    await expect(modal.getByRole('heading', { name, exact: true })).toBeFocused();
    expect(await back.evaluate(node => Boolean(node.closest('[inert]')))).toBe(true);
    const close = modal.getByRole('button', { name: ko ? '예시 상세 닫기' : 'Close example detail', exact: true });
    const full = modal.getByRole('button', { name: ko ? '전체 측정값' : 'Full measurements', exact: true });
    await page.keyboard.press('Shift+Tab'); await expect(full).toBeFocused();
    await page.keyboard.press('Tab'); await expect(close).toBeFocused();
    await page.keyboard.press('Shift+Tab'); await expect(full).toBeFocused();
    await full.click();
    await expect(modal.getByRole('region', { name: ko ? '보조 측정값' : 'Supporting measurements', exact: true })).toBeVisible();
    await selector.selectOption('0');
    await expect(modal.getByRole('region', { name: ko ? '보조 측정값' : 'Supporting measurements', exact: true })).toHaveCount(0);
    for (const reflowWidth of [640, 320]) {
      await page.setViewportSize({ width: reflowWidth, height: 450 });
      await full.click();
      const box = await modal.boundingBox();
      expect(box!.x).toBeGreaterThanOrEqual(0); expect(box!.x + box!.width).toBeLessThanOrEqual(reflowWidth);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      expect(await modal.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
      expect(await page.locator('*').count()).toBeLessThan(500);
      await page.screenshot({ path: info.outputPath(`reflow-${reflowWidth}.png`) });
    }
    await close.click(); await expect(selector).toBeFocused();
    await expect(page.locator('[inert]')).toHaveCount(0);
    await info.attach('zoom-reflow-method', { body: JSON.stringify({ method: 'CSS viewport resize, not native browser zoom or DPR-only emulation', desktop: [1280, 900], twoHundredPercentEquivalent: [640, 450], additionalNarrowWidth: 320 }), contentType: 'application/json' });
    expect(errors).toEqual([]); expect(requests.every(r => r.startsWith('GET '))).toBe(true);
  });
  for (let groupPage = 0; groupPage < 13; groupPage++) {
    test(`progressive all evidence page ${groupPage + 1} ${width}px ${language}`, async ({ page }, info) => {
      const { requests, errors } = await setup(page, width, language);
      await page.goto('/analyses/progressive-a');
      const glance = page.getByRole('region', { name: ko ? '한눈에 보기' : 'At a glance', exact: true });
      await expect(glance).toBeVisible();
      await expect(glance.getByTestId('top-observation')).toHaveCount(3);
      const counts: number[] = [];
      const bound = async () => {
        const geometry = await page.evaluate(() => ({ nodes: document.querySelectorAll('*').length, body: document.body.scrollWidth, root: document.documentElement.scrollWidth }));
        counts.push(geometry.nodes);
        expect(geometry.nodes).toBeLessThan(500);
        expect(geometry.body).toBeLessThanOrEqual(width);
        expect(geometry.root).toBeLessThanOrEqual(width);
      };
      await bound();
      if (groupPage === 0) await page.screenshot({ path: info.outputPath(`overview-${width}-${language}.png`), fullPage: true });
      await page.getByRole('button', { name: ko ? '전체 이상 항목 보기' : 'View all anomaly items', exact: true }).click();
      const next = page.getByRole('button', { name: ko ? '다음 그룹' : 'Next groups', exact: true });
      for (let p = 0; p < groupPage; p++) await next.click();
      const issues: PatternIssue[] = maximum.many.issues.slice(groupPage * 8, groupPage * 8 + 8);
      let visited = 0;
      const inventory: { issue: string; example: number }[] = [];
      for (const [i, issue] of issues.entries()) {
        const article = page.locator('.network-report article').nth(i);
        await expect(article).toContainText(issue.id);
        const toggle = article.getByRole('button', { name: /representative evidence|대표 증거/ });
        await toggle.focus(); await page.keyboard.press(i % 2 ? 'Space' : 'Enter');
        const evidence = page.getByRole('region', { name: ko ? '대표 흐름 증거' : 'Representative flow evidence', exact: true });
        await expect(evidence).toHaveCount(1);
        await expect(page.getByRole('region', { name: ko ? '보조 측정값' : 'Supporting measurements', exact: true })).toHaveCount(0);
        for (const name of ko ? ['가능한 원인 — 가설', '대표 증거', '불확실성', '다음 확인 사항'] : ['Possible cause — hypothesis', 'Representative proof', 'Uncertainty', 'Next checks']) await expect(evidence.getByRole('heading', { name, exact: true })).toBeVisible();
        const selector = page.getByLabel(ko ? '대표 예시' : 'Representative example', { exact: true });
        await expect(selector.locator('option')).toHaveCount(issue.examples.length + 1);
        for (const [ordinal, example] of issue.examples.entries()) {
          await selector.selectOption(String(ordinal));
          const selected = page.getByRole(width < 1200 ? 'dialog' : 'region', { name: ko ? '선택한 대표 예시' : 'Selected representative example', exact: true });
          await expect(selected).toContainText(example.endpoint_a.ip);
          for (const [key, value] of Object.entries(example.facts ?? {})) await expect(selected.getByText(`${factLabel(language, key)}: ${value}`, { exact: true })).toBeVisible();
          await selected.getByRole('button', { name: ko ? '전체 측정값' : 'Full measurements', exact: true }).click();
          const measurement = page.getByRole('region', { name: ko ? '보조 측정값' : 'Supporting measurements', exact: true });
          await expect(measurement).toHaveCount(1);
          await expect(measurement).toContainText(ko ? '대표성은 확립되지 않음' : 'representativeness not established');
          await expect(measurement).toContainText(ko ? '제외된 후보 일치' : 'Excluded candidate matches');
          type Stats = { count: number; mean: number | null; min: number | null; max: number | null; stddev: number | null };
          type TTL = { count: number; min: number | null; max: number | null; changes: number; missing: number };
          const m = example.measurements as { observed_rtt_ms: Stats; interarrival_variation_ms: Record<string, Stats>; ttl_observed: Record<string, TTL>; rtt_sources: { syn_ack: number; data_ack: number }; rtt_excluded: { ambiguous: number; nonpositive_time: number; nonexact_ack: number } };
          const unknown = ko ? '알 수 없음' : 'Unknown';
          const stats = (s: Stats) => `${ko ? '표본' : 'Samples'}: ${s.count} · ${ko ? '평균 / 최소 / 최대' : 'mean / min / max'}: ${[s.mean, s.min, s.max].map(n => s.count ? String(n) : unknown).join(' / ')} · ${ko ? '산포 (모집단 표준편차)' : 'dispersion (population stddev)'}: ${s.count > 1 ? s.stddev : unknown}`;
          await expect(measurement).toContainText(stats(m.observed_rtt_ms));
          for (const [direction, arrow] of [['a_to_b', 'A → B'], ['b_to_a', 'B → A']]) {
            await expect(measurement).toContainText(`${arrow}: ${stats(m.interarrival_variation_ms[direction])}`);
            const s = m.ttl_observed[direction];
            await expect(measurement).toContainText(`${arrow}: ${ko ? '표본' : 'Samples'} ${s.count} · ${ko ? '최소 / 최대' : 'min / max'} ${s.count ? s.min : unknown} / ${s.count ? s.max : unknown} · ${ko ? '변화' : 'changes'} ${s.changes} · ${ko ? '누락' : 'missing'} ${s.missing}`);
          }
          await expect(measurement).toContainText(`SYN/ACK ${m.rtt_sources.syn_ack} · ${ko ? '데이터/ACK' : 'Data/ACK'} ${m.rtt_sources.data_ack}`);
          await expect(measurement).toContainText(`${ko ? '모호함 / 재전송' : 'ambiguous / retransmitted'} ${m.rtt_excluded.ambiguous} · ${ko ? '0 이하 시간' : 'nonpositive time'} ${m.rtt_excluded.nonpositive_time} · ${ko ? '정확히 일치하지 않는 ACK' : 'nonexact ACK'} ${m.rtt_excluded.nonexact_ack}`);
          await expect(measurement).toContainText(ko ? '도착 간격 산포' : 'Interarrival dispersion');
          await expect(measurement).toContainText(ko ? 'IPv4 TTL / IPv6 홉 제한' : 'IPv4 TTL / IPv6 Hop Limit');
          if (groupPage === 0 && i === 0 && ordinal === 0) await page.screenshot({ path: info.outputPath(`selected-detail-${width}-${language}.png`), fullPage: true });
          await bound(); visited++; inventory.push({ issue: issue.id, example: ordinal });
        }
        await page.getByRole('button', { name: ko ? '예시 상세 닫기' : 'Close example detail', exact: true }).click();
        await expect(selector).toBeFocused();
        await expect(page.getByRole('region', { name: ko ? '보조 측정값' : 'Supporting measurements', exact: true })).toHaveCount(0);
        await toggle.focus(); await page.keyboard.press('Enter');
        await expect(evidence).toHaveCount(0); await expect(toggle).toBeFocused();
        await bound();
      }
      expect(visited).toBe(issues.reduce((n, issue) => n + issue.examples.length, 0));
      if (groupPage === 12) await expect(next).toBeDisabled();
      expect(errors).toEqual([]); expect(requests.every(r => r.startsWith('GET '))).toBe(true);
      await info.attach('progressive-traversal', { body: JSON.stringify({ groupPage, visited, inventory, initial: counts[0], peak: Math.max(...counts), counts, requests }), contentType: 'application/json' });
    });
  }
  test(`progressive numeric citation and cached source transitions ${width}px ${language}`, async ({ page }, info) => {
    const { requests, errors } = await setup(page, width, language);
    await page.goto('/analyses/numeric-job');
    const ai = page.getByRole('button', { name: ko ? 'AI 해석 열기' : 'Open AI interpretation', exact: true });
    await ai.click();
    const facts = page.getByRole('region', { name: ko ? '검증된 수치 출처 사실' : 'Verified numeric source facts' });
    const citation = facts.getByRole('button', { name: /original example|원본 예시/ }).first();
    await expect(citation).toBeVisible(); const before = [...requests];
    await citation.focus(); await page.keyboard.press('Enter');
    await expect(page.getByLabel(ko ? '대표 예시' : 'Representative example', { exact: true })).toHaveValue('0');
    const measurement = page.getByRole('region', { name: ko ? '보조 측정값' : 'Supporting measurements', exact: true });
    await expect(measurement).toContainText('100 / 100 / 100');
    await expect(measurement).not.toContainText(ko ? '도착 간격 산포 (ms)' : 'Interarrival dispersion (ms)');
    expect(requests).toEqual(before);
    await expect(facts).toHaveCount(0);
    expect(await page.locator('*').count()).toBeLessThan(500);
    await page.keyboard.press('Escape');
    await expect(page.getByRole('heading', { name: ko ? '그룹별 관찰 결과' : 'Grouped observations', exact: true })).toBeFocused();
    await page.getByRole('link', { name: 'Back to analysis history' }).click();
    await page.getByRole('link', { name: 'progressive-b', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'progressive-b', exact: true })).toBeVisible();
    await expect(measurement).toHaveCount(0);
    await page.getByRole('link', { name: 'Back to analysis history' }).click();
    await page.getByRole('link', { name: 'Numeric source', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Numeric source', exact: true })).toBeVisible();
    await expect(page.locator('[id^="network-evidence-"]')).toHaveCount(0);
    await ai.click(); await facts.getByRole('button', { name: /original example|원본 예시/ }).first().click();
    await expect(measurement).toContainText('100 / 100 / 100');
    await info.attach('citation-requests', { body: JSON.stringify(requests), contentType: 'application/json' });
    expect(errors).toEqual([]); expect(requests.every(r => r.startsWith('GET '))).toBe(true);
  });
}
