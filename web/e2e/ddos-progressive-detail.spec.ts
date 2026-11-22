import { test, expect, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
const omittedReport = JSON.parse(execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python'), ['tests/ddos_omission_fixture.py'], { encoding: 'utf8' }));

const load = (name: string) => name === 'omission' ? { ...JSON.parse(readFileSync('../controller/tests/fixtures/pcap_attack_guidance/positive.job.json', 'utf8')), ddos_attack: omittedReport } : JSON.parse(readFileSync(`../controller/tests/fixtures/pcap_attack_guidance/${name}.job.json`, 'utf8'));
const envelope = (name: string) => ({
  ...load(name), name: 'Long incident identifier and analyst-owned report title — '.repeat(12),
  description: 'Retained analyst note with full source and processing context. '.repeat(30),
  source: { filename: 'capture-'.repeat(30) + '.pcap', sha256: 'a'.repeat(64), capture_format: 'PCAP', size_bytes: 123456, packet_bytes_retained: true, captured_packet_count: 1200, parsed_packet_count: 1197, skipped_packet_count: 3, link_types: [1] },
  warnings: ['Capture quality is qualified; review parser and retention limits.'],
  processing: { phase: 'COMPLETED', attempt: 1, updated_at: '2026-09-15T01:00:00Z' },
  created_at: '2026-09-15T00:00:00Z', completed_at: '2026-09-15T01:00:00Z',
  transitions: [{ from_status: 'ANALYZING', to_status: 'COMPLETED', occurred_at: '2026-09-15T01:00:00Z', reason: 'Completed offline fixture analysis' }],
});
async function install(page: Page, language: string, name = 'positive') {
  const job = envelope(name), writes: string[] = [], errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(lang => { localStorage.setItem('c2hunter-token', 'owned-fixture'); localStorage.setItem('c2hunter-report-language', lang); }, language);
  await page.route('**/api/v1/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname.replace('/api/v1', '');
    if (request.method() !== 'GET') writes.push(path);
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify(path === `/analysis-jobs/${job.id}` ? job : path === '/ai-capabilities' ? { available: false, ddos_interpretation: false, reason: 'Offline fixture' } : { items: [] }) });
  });
  await page.goto(`/analyses/${job.id}`);
  return { job, writes, errors };
}
async function closeNarrowDetail(page: Page) {
  if (await page.getByRole('dialog').count()) await page.getByRole('button', { name: /Close detail|상세 닫기/ }).click();
}
const geometry = (page: Page) => page.evaluate(() => ({ nodes: document.querySelectorAll('*').length, width: innerWidth, scroll: document.documentElement.scrollWidth }));
for (const width of [1280, 390]) for (const language of ['en', 'ko']) test(`progressive hierarchy full metadata ${width} ${language}`, async ({ page }, info) => {
  await page.setViewportSize({ width, height: 900 });
  const { job, writes, errors } = await install(page, language);
  const en = language === 'en';
  const glance = page.getByRole('region', { name: en ? 'DDoS at a glance' : 'DDoS 한눈에 보기' });
  await expect(glance).toBeVisible();
  await expect(glance).toContainText(en ? 'No qualified baseline; possible only.' : '적격 기준선 없음; 가능성 수준만 평가.');
  await expect(glance).toContainText(en ? 'The observation window is short.' : '관찰 구간이 짧습니다.');
  await page.screenshot({ path: info.outputPath(`overview-${width}-${language}.png`) });
  const next = page.getByRole('region', { name: en ? 'Next check' : '다음 확인' });
  const box = await next.boundingBox();
  const warnings = glance.locator('.warning');
  expect(await warnings.count()).toBeGreaterThan(0);
  const warningBoxes = [];
  for (const warning of await warnings.all()) {
    const bounds = (await warning.boundingBox())!;
    warningBoxes.push(bounds);
    expect(bounds.y + bounds.height).toBeLessThanOrEqual(box!.y);
    expect(bounds.y + bounds.height).toBeLessThanOrEqual(900);
  }
  expect(box!.y).toBeGreaterThanOrEqual(0);
  expect(box!.y + box!.height).toBeLessThanOrEqual(900);
  const initial = await geometry(page); expect(initial.nodes).toBeLessThan(900); expect(initial.scroll).toBeLessThanOrEqual(width);
  await expect(page.getByRole('heading', { name: 'Analyst note' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: /Review window 1|검토 구간 1/ })).toHaveCount(0);
  await page.getByRole('button', { name: en ? 'Analysis coverage and limitations' : '분석 범위와 한계' }).click();
  await expect(page.getByRole('region', { name: en ? 'DDoS analysis coverage' : 'DDoS 분석 범위' })).toContainText(en ? 'No qualified baseline; classification is limited to possible.' : '적격 기준선이 없어 가능성 수준으로 제한됩니다.');
  await page.getByRole('button', { name: en ? 'Analysis coverage and limitations' : '분석 범위와 한계' }).click();
  await next.getByRole('button').click();
  await page.getByRole('button', { name: /Inspect candidate|후보 검토/ }).first().click();
  await expect(page.getByRole('region', { name: en ? 'Candidate inspection' : '후보 검토 상세' })).toBeVisible();
  await page.screenshot({ path: info.outputPath(`selected-detail-${width}-${language}.png`) });
  await closeNarrowDetail(page);
  await page.getByRole('button', { name: en ? 'Open PCAP review windows' : 'PCAP 검토 구간 열기' }).click();
  await expect(page.getByRole('region', { name: en ? 'DDoS finding evidence' : 'DDoS 발견 근거' })).toHaveCount(0);
  await page.getByRole('button', { name: en ? 'Review window 1' : '검토 구간 1', exact: true }).click();
  await expect(page.getByRole('region', { name: en ? 'Candidate evidence' : '후보 근거' })).toContainText(job.pcap_attack_guidance.candidates[0].target.ip);
  await closeNarrowDetail(page);
  await page.getByRole('button', { name: en ? 'Open DDoS AI interpretation' : 'DDoS AI 해석 열기' }).click();
  await expect(page.getByRole('region', { name: en ? 'Candidate evidence' : '후보 근거' })).toHaveCount(0);
  await page.getByRole('button', { name: en ? 'Analysis coverage and limitations' : '분석 범위와 한계' }).click();
  await expect(page.getByRole('region', { name: en ? 'DDoS analysis coverage' : 'DDoS 분석 범위' })).toContainText(en ? 'No qualified baseline; classification is limited to possible.' : '적격 기준선이 없어 가능성 수준으로 제한됩니다.');
  await page.getByRole('button', { name: en ? 'Analysis coverage and limitations' : '분석 범위와 한계' }).click();
  await next.getByRole('button').click();
  await expect(page.getByRole('region', { name: en ? 'Candidate inspection' : '후보 검토 상세' })).toBeVisible();
  const expanded = await geometry(page); expect(expanded.nodes).toBeLessThan(900); expect(expanded.scroll).toBeLessThanOrEqual(width);
  await closeNarrowDetail(page);
  await page.getByRole('button', { name: '작업 상세 / Job details' }).click();
  await expect(page.getByRole('heading', { name: 'Analyst note' })).toBeVisible();
  await expect(page.getByText(job.description, { exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: job.name, exact: true })).toBeVisible();
  expect(writes).toEqual([]); expect(errors).toEqual([]);
  await info.attach('geometry', { body: JSON.stringify({ initial, expanded, next: box, warningBoxes }), contentType: 'application/json' });
});

for (const width of [1280, 390]) for (const language of ['en', 'ko']) test(`maximum PCAP all windows full metadata ${width} ${language}`, async ({ page }, info) => {
  await page.setViewportSize({ width, height: 900 });
  const { job, writes, errors } = await install(page, language, 'overflow');
  const en = language === 'en';
  await expect(page.getByRole('region', { name: en ? 'PCAP review guidance' : 'PCAP 검토 안내' })).toBeVisible();
  const initial = await geometry(page); expect(initial.nodes).toBeLessThan(900);
  await page.getByRole('button', { name: en ? 'PCAP coverage and limitations' : 'PCAP 관찰 범위와 한계' }).click();
  await closeNarrowDetail(page);
  await page.getByRole('button', { name: en ? 'Open PCAP review windows' : 'PCAP 검토 구간 열기' }).click();
  const seen: string[] = []; let peak = initial.nodes;
  for (let p = 0; p < 4; p++) {
    const buttons = page.getByRole('button', { name: en ? /^Review window \d+$/ : /^검토 구간 \d+$/ });
    await expect(buttons).toHaveCount(8);
    for (let i = 0; i < 8; i++) {
      await buttons.nth(i).click();
      const evidence = page.getByRole('region', { name: en ? 'Candidate evidence' : '후보 근거' });
      await expect(evidence).toHaveCount(1);
      const candidate = job.pcap_attack_guidance.candidates[p * 8 + i];
      await expect(evidence).toContainText(candidate.target.ip);
      await expect(evidence).toContainText(candidate.window_start);
      await expect(evidence).toContainText(candidate.window_end);
      seen.push(candidate.target.ip);
      const g = await geometry(page); peak = Math.max(peak, g.nodes); expect(g.scroll).toBeLessThanOrEqual(width);
      await closeNarrowDetail(page);
    }
    if (p < 3) await page.getByRole('button', { name: en ? 'Next candidate page' : '다음 후보 페이지' }).click();
  }
  expect(seen).toEqual(job.pcap_attack_guidance.candidates.map((c: { target: { ip: string } }) => c.target.ip));
  expect(peak).toBeLessThan(900);
  await closeNarrowDetail(page);
  await page.getByRole('button', { name: en ? 'Open DDoS AI interpretation' : 'DDoS AI 해석 열기' }).click();
  await expect(page.getByRole('region', { name: en ? 'PCAP coverage and limitations' : 'PCAP 관찰 범위와 한계' })).toBeVisible();
  await expect(page.getByRole('region', { name: en ? 'Candidate evidence' : '후보 근거' })).toHaveCount(0);
  expect(writes).toEqual([]); expect(errors).toEqual([]);
  await info.attach('maximum-dom', { body: JSON.stringify({ initial, peak, reached: seen.length }), contentType: 'application/json' });
});

for (const width of [1280, 390]) for (const kind of ['finding', 'window']) test(`responsive detail Escape and focus ${width} ${kind}`, async ({ page }) => {
  await page.setViewportSize({ width, height: 900 });
  await install(page, 'en');
  if (kind === 'window') await page.getByRole('button', { name: 'Open PCAP review windows' }).click();
  const invoker = kind === 'finding' ? page.getByRole('button', { name: /Show detailed evidence/ }) : page.getByRole('button', { name: 'Review window 1', exact: true });
  await invoker.click();
  const detail = page.getByRole(width < 600 ? 'dialog' : 'region', { name: kind === 'finding' ? 'DDoS detail' : 'PCAP window detail', exact: true });
  await expect(detail).toBeVisible();
  await expect(detail.getByRole('heading').first()).toBeFocused();
  if (width < 600) {
    await page.keyboard.press('Shift+Tab');
    expect(await detail.evaluate(el => el.contains(document.activeElement))).toBe(true);
    await page.setViewportSize({ width: 1280, height: 900 });
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await page.setViewportSize({ width: 390, height: 900 });
    await expect(detail).toBeVisible();
  } else await expect(page.getByRole('dialog')).toHaveCount(0);
  await page.keyboard.press('Escape');
  await expect(detail).toHaveCount(0);
  await expect(invoker).toBeFocused();
});

for (const width of [1280, 390]) for (const language of ['en', 'ko']) test(`partial capture critical warnings first fold ${width} ${language}`, async ({ page }, info) => {
  await page.setViewportSize({ width, height: 900 });
  await install(page, language, 'partial');
  const glance = page.getByRole('region', { name: language === 'en' ? 'DDoS at a glance' : 'DDoS 한눈에 보기' });
  await expect(glance).toBeVisible();
  for (const phrase of language === 'en' ? ['parser skipped', 'capture or dataset is partial', 'observation window is short', 'Counts are lower bounds', 'Coverage is incomplete'] : ['파서가', '부분적입니다', '관찰 구간이 짧습니다', '수치는 하한', '분석 범위가 불완전']) await expect(glance).toContainText(phrase);
  const next = (await page.getByRole('region', { name: language === 'en' ? 'Next check' : '다음 확인' }).boundingBox())!;
  const warnings = [];
  for (const node of await glance.locator('.warning').all()) {
    const box = (await node.boundingBox())!; warnings.push(box);
    expect(box.y + box.height).toBeLessThanOrEqual(next.y);
  }
  expect(next.y + next.height).toBeLessThanOrEqual(900);
  await page.screenshot({ path: info.outputPath('partial-firstfold.png') });
  await info.attach('critical-warning-bounds', { body: JSON.stringify({ next, warnings }), contentType: 'application/json' });
});

for (const width of [1280, 390]) for (const language of ['en', 'ko']) test(`producer omission lower bounds first fold ${width} ${language}`, async ({ page }, info) => {
  await page.setViewportSize({ width, height: 900 });
  const { job } = await install(page, language, 'omission');
  const glance = page.getByRole('region', { name: language === 'en' ? 'DDoS at a glance' : 'DDoS 한눈에 보기' });
  await expect(glance).toBeVisible();
  await expect(glance).toContainText(language === 'en' ? 'Findings omitted by producer: ' + job.ddos_attack.omitted_finding_count : '생산자가 생략한 발견 항목: ' + job.ddos_attack.omitted_finding_count);
  await expect(glance).toContainText(language === 'en' ? 'Counts are lower bounds' : '수치는 하한');
  const next = (await page.getByRole('region', { name: language === 'en' ? 'Next check' : '다음 확인' }).boundingBox())!;
  const warnings = [];
  for (const node of await glance.locator('.warning').all()) {
    const box = (await node.boundingBox())!; warnings.push(box);
    expect(box.y + box.height).toBeLessThanOrEqual(next.y);
  }
  expect(next.y + next.height).toBeLessThanOrEqual(900);
  await page.screenshot({ path: info.outputPath('omission-firstfold.png') });
  await info.attach('omission-warning-bounds', { body: JSON.stringify({ next, warnings }), contentType: 'application/json' });
});

test('detail restores a missing invoker to the report heading', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 900 });
  await install(page, 'en');
  const invoker = page.getByRole('button', { name: /Show detailed evidence/ });
  const original = await invoker.elementHandle();
  await invoker.click();
  await original!.evaluate(el => el.remove());
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect(page.locator('#ddos-heading')).toBeFocused();
});

for (const outcome of ['success', 'error']) test(`modal keeps pending AI accessible through deferred ${outcome}`, async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 900 });
  const { errors } = await install(page, 'en');
  await page.route('**/api/v1/ai-capabilities', route => route.fulfill({ json: { available: true, ddos_interpretation: true, remote: false } }));
  await page.reload();
  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  const posts: unknown[] = [];
  const accepted = { id: 'visible-ai', status: 'QUEUED', analysis_kind: 'DDOS_ATTACK', language: 'en' };
  await page.route('**/api/v1/ai-runs/visible-ai', route => route.fulfill({ json: accepted }));
  await page.route('**/api/v1/analysis-jobs/*/ai-runs', async route => {
    if (route.request().method() === 'GET') return route.fulfill({ json: { items: [] } });
    posts.push(route.request().postDataJSON());
    await pending;
    await route.fulfill(outcome === 'success' ? { status: 201, json: accepted } : { status: 503, json: { error: { code: 'UNCONFIRMED', message: 'Deferred failure' } } });
  });
  try {
    await page.getByRole('button', { name: 'Open DDoS AI interpretation' }).click();
    await page.getByRole('button', { name: 'Run DDoS AI interpretation' }).click();
    await expect.poll(() => posts.length).toBe(1);
    await page.getByRole('button', { name: /Show detailed evidence/ }).click();
    const modal = page.getByRole('dialog');
    await expect(modal.getByText('AI request pending — admission not yet confirmed.')).toBeVisible();
    await expect(modal.getByRole('button', { name: 'Return to DDoS AI interpretation' })).toBeVisible();
    await modal.getByRole('button', { name: 'Return to DDoS AI interpretation' }).click();
    await expect(modal).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Starting…' })).toBeDisabled();
    await page.getByRole('button', { name: 'Open PCAP review windows' }).click();
    await page.getByRole('button', { name: 'Review window 1', exact: true }).click();
    await expect(modal.getByText('AI request pending — admission not yet confirmed.')).toBeVisible();
    release();
    await expect(modal.getByText(outcome === 'success' ? 'QUEUED' : 'AI admission unconfirmed. Review the request before trying again.', { exact: true })).toBeVisible();
    await modal.getByRole('button', { name: 'Return to DDoS AI interpretation' }).click();
    await expect(modal).toHaveCount(0);
    expect(posts).toHaveLength(1); expect(errors).toEqual([]);
  } finally { release(); }
});

for (const kind of ['finding', 'window']) test(`200 percent text zoom and half-width reflow ${kind}`, async ({ page }, info) => {
  // CSS text enlargement + 1280/2 CSS-pixel layout checks; deviceScaleFactor
  // is deliberately NOT used or described as browser zoom.
  await page.setViewportSize({ width: 640, height: 450 });
  await install(page, 'en');
  await page.addStyleTag({ content: 'html { font-size: 200%; }' });
  if (kind === 'window') await page.getByRole('button', { name: 'Open PCAP review windows' }).click();
  await page.getByRole('button', { name: kind === 'finding' ? /Show detailed evidence/ : /^Review window 1$/ }).click();
  let g = await geometry(page); expect(g.scroll).toBeLessThanOrEqual(g.width);
  await page.setViewportSize({ width: 390, height: 900 });
  const modal = page.getByRole('dialog');
  await expect(modal).toBeVisible();
  expect(await modal.evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
  await page.keyboard.press('Escape');
  await expect(modal).toHaveCount(0);
  g = await geometry(page);
  await info.attach('overflow-observations', { body: JSON.stringify(await page.locator('body *').evaluateAll(elements => elements.filter(el => el.getBoundingClientRect().right > innerWidth + 1).map(el => ({ tag: el.tagName, class: el.className, text: el.textContent?.slice(0, 100), right: el.getBoundingClientRect().right })))), contentType: 'application/json' });
  expect(g.scroll).toBeLessThanOrEqual(g.width);
  await info.attach('reflow', { body: JSON.stringify(g), contentType: 'application/json' });
});

test('pending AI and explicit reference stay owned across finding, PCAP and AI switches in the built App', async ({ page }) => {
  const { job, writes, errors } = await install(page, 'en');
  const normal = envelope('clean_payload');
  await page.route('**/api/v1/analysis-jobs?*', route => route.fulfill({ json: { items: [normal], total: 1, page: 1, page_size: 20 } }));
  await page.route('**/api/v1/ai-capabilities', route => route.fulfill({ json: { available: true, ddos_interpretation: true, remote: true, destination: 'https://model.invalid', provider: 'fixture', model_name: 'fixture' } }));
  // Reload only to establish the different capability fixture before any admission.
  await page.reload();
  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  const posts: { path: string; body: Record<string, unknown> }[] = [];
  const accepted = { id: 'pending-ai', status: 'QUEUED', analysis_kind: 'DDOS_ATTACK', language: 'en' };
  await page.route('**/api/v1/ai-runs/pending-ai', route => route.fulfill({ json: accepted }));
  await page.route('**/api/v1/analysis-jobs/*/ai-runs', async route => {
    if (route.request().method() === 'GET') return route.fulfill({ json: { items: [] } });
    posts.push({ path: new URL(route.request().url()).pathname, body: route.request().postDataJSON() });
    await pending; await route.fulfill({ status: 201, json: accepted });
  });
  try {
    await page.getByLabel('Normal reference action').selectOption('select');
    await page.getByRole('radio').check();
    await page.getByRole('button', { name: /Show detailed evidence/ }).click();
    await page.getByRole('button', { name: /Inspect candidate/ }).click();
    await page.getByRole('button', { name: 'Open PCAP review windows' }).click();
    await page.getByRole('button', { name: 'Review window 1', exact: true }).click();
    await page.getByRole('button', { name: 'Open DDoS AI interpretation' }).click();
    await page.getByLabel('I consent to this remote destination.').check();
    await page.getByRole('button', { name: 'Run DDoS AI interpretation' }).click();
    await expect.poll(() => posts.length).toBe(1);
    await page.getByRole('button', { name: /Show detailed evidence/ }).click();
    await expect(page.getByRole('region', { name: 'Candidate inspection' })).toBeVisible();
    await page.getByRole('button', { name: 'Open PCAP review windows' }).click();
    await page.getByRole('button', { name: 'Open DDoS AI interpretation' }).click();
    await expect(page.getByRole('button', { name: 'Starting…' })).toBeDisabled();
    await expect(page.getByLabel('I consent to this remote destination.')).toBeChecked();
    await expect(page.getByRole('radio')).toBeChecked();
    release();
    await expect(page.getByRole('button', { name: 'Cancel AI run' })).toBeVisible();
    await page.getByRole('button', { name: /Show detailed evidence/ }).click();
    await expect(page.getByRole('button', { name: 'Cancel AI run' })).toBeVisible();
    expect(posts).toHaveLength(1);
    expect(posts[0]).toMatchObject({ path: `/api/v1/analysis-jobs/${job.id}/ai-runs`, body: { analysis_kind: 'DDOS_ATTACK', language: 'en', allow_remote: true } });
    expect(writes).toEqual([]); expect(errors).toEqual([]);
  } finally { release(); }
});
