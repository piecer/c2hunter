import { withLegacyAuthentication } from './auth-fixture';
import { expect, test } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
const python = process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python');
const network = JSON.parse(execFileSync(python, ['tests/network_report_fixture.py', '--pagination'], { encoding: 'utf8' }))['20'];
const networkJob = JSON.parse(execFileSync(python, ['tests/network_public_job_fixture.py'], { input: JSON.stringify(network), encoding: 'utf8' }));
const ddosJob = JSON.parse(readFileSync('../controller/tests/fixtures/pcap_attack_guidance/positive.job.json', 'utf8'));
for (const width of [1280, 390]) for (const language of ['en', 'ko']) for (const module of ['network', 'ddos']) for (const beforeAck of [false, true]) {
  test(`isolated ${module} cancel ${width}px ${language} B before A ACK=${beforeAck}`, async ({ page }, info) => {
    const t = (en: string, ko: string) => language === 'ko' ? ko : en;
    await page.setViewportSize({ width, height: 900 });
    await page.addInitScript(lang => { localStorage.setItem('c2hunter-token', 'fixture'); localStorage.setItem('c2hunter-report-language', lang); }, language);
    const job = module === 'network' ? networkJob : ddosJob;
    const a = { id: 'A opaque:% 한', analysis_kind: module === 'network' ? 'NETWORK_ANOMALY' : 'DDOS_ATTACK', status: 'ANALYZING', language: 'en', analysis_job_id: job.id, dataset_id: job.dataset_id, created_at: '2026-11-01T00:00:00Z' };
    const b = { ...a, id: 'B opaque:% 한', created_at: '2026-11-02T00:00:00Z' };
    const aPath = `/ai-runs/${encodeURIComponent(a.id)}`, bPath = `/ai-runs/${encodeURIComponent(b.id)}`;
    let releaseA!: () => void, releaseB!: () => void;
    const heldA = new Promise<void>(r => { releaseA = r; }), heldB = new Promise<void>(r => { releaseB = r; });
    let sourceError = false, newer = false, unreadable = false;
    const posts: string[] = [], reads: string[] = [], errors: string[] = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.route('**/api/v1/**', withLegacyAuthentication(async route => {
      const request = route.request(), url = new URL(request.url()), path = url.pathname.replace('/api/v1', '');
      if (request.method() === 'POST') {
        posts.push(path);
        expect(request.postDataJSON()).toEqual({ reason: 'operator requested from web console' });
        if (path === `${aPath}/cancel`) { await heldA; await route.fulfill({ json: { ...a, status: 'CANCELLED' } }); }
        else if (path === `${bPath}/cancel`) { await heldB; await route.fulfill({ status: 503, json: {} }); }
        else await route.fulfill({ status: 400, json: {} });
        return;
      }
      reads.push(path);
      if (path === `/analysis-jobs/${job.id}`) await route.fulfill({ status: sourceError ? 503 : 200, json: sourceError ? {} : job });
      else if (path === `/analysis-jobs/${job.id}/ai-runs`) await route.fulfill({ status: sourceError ? 503 : 200, json: sourceError ? {} : { items: newer ? [b, a] : [a], current_page: 1, page_size: 50, total: newer ? 2 : 1 } });
      else if (path === '/ai-capabilities') await route.fulfill({ json: { available: true, network_interpretation: true, ddos_interpretation: true, remote: false } });
      else if (path === aPath) await route.fulfill({ status: unreadable ? 503 : 200, json: unreadable ? {} : a });
      else if (path === bPath) await route.fulfill({ json: b });
      else await route.fulfill({ json: { items: [] } });
    }));
    await page.goto(`/analyses/${job.id}`);
    const openName = module === 'network' ? t('Open AI interpretation', 'AI 해석 열기') : t('Open DDoS AI interpretation', 'DDoS AI 해석 열기');
    await page.getByRole('button', { name: openName, exact: true }).click();
    const cancel = () => page.getByRole('button', { name: t('Cancel AI run', 'AI 실행 취소'), exact: true });
    await cancel().click();
    await expect.poll(() => posts).toEqual([`${aPath}/cancel`]);
    sourceError = true;
    // Exercise the shipped reconnect refresh after its unchanged 10s stale time;
    // no QueryClient access, route departure, reload or source-owner replacement.
    await page.waitForTimeout(10100);
    await page.evaluate(() => { window.dispatchEvent(new Event('offline')); window.dispatchEvent(new Event('online')); });
    const recover = page.getByRole('button', { name: '다시 시도', exact: true });
    await expect(recover).toBeVisible();
    await expect(page.getByRole('group', { name: `${t('Cancellation receipt', '취소 응답 기록')} ${a.id}`, exact: true })).toContainText(t('AI cancellation pending', 'AI 취소 대기 중'));
    sourceError = false; newer = true; unreadable = true;
    await recover.click();
    await expect(page.getByRole('button', { name: openName, exact: true })).toBeVisible();
    await expect.poll(() => reads.includes(bPath)).toBe(true);
    await page.getByRole('button', { name: openName, exact: true }).click();
    if (module === 'ddos') {
      await page.getByRole('button', { name: /Show detailed evidence|상세 근거 보기/ }).click();
      const detail = page.getByRole(width === 390 ? 'dialog' : 'region', { name: t('DDoS detail', 'DDoS 상세'), exact: true });
      await expect(detail).toBeVisible();
      if (width === 390) await expect(detail).toHaveAttribute('aria-modal', 'true');
      if (width === 390) await expect(detail.getByRole('button', { name: t('Cancel AI run', 'AI 실행 취소'), exact: true })).toBeVisible();
    }
    await expect(cancel()).toBeEnabled();
    if (beforeAck) await cancel().click();
    releaseA();
    const receiptA = page.getByRole('group', { name: `${t('Cancellation receipt', '취소 응답 기록')} ${a.id}`, exact: true });
    await expect(receiptA).toContainText(t('AI cancellation unconfirmed', 'AI 취소 미확인'));
    await receiptA.getByRole('button', { name: t('Reconcile cancellation status', '취소 상태 확인') }).click();
    await expect(receiptA).toContainText(t('Matching run status remains unknown.', '해당 실행 상태는 아직 알 수 없습니다.'));
    if (!beforeAck) { await expect(cancel()).toBeEnabled(); await cancel().click(); }
    await expect.poll(() => posts).toEqual([`${aPath}/cancel`, `${bPath}/cancel`]);
    const receiptB = page.getByRole('group', { name: `${t('Cancellation receipt', '취소 응답 기록')} ${b.id}`, exact: true });
    await expect(receiptB).toContainText(t('AI cancellation pending', 'AI 취소 대기 중'));
    await page.screenshot({ path: info.outputPath('isolated-cancellation.png') });
    await info.attach('accessibility', { body: await page.locator('main').ariaSnapshot(), contentType: 'text/plain' });
    releaseB();
    await expect(receiptB).toContainText(t('AI cancellation unconfirmed', 'AI 취소 미확인'));
    await expect(receiptA).toContainText(t('AI cancellation unconfirmed', 'AI 취소 미확인'));
    await expect(cancel()).toBeDisabled();
    expect(posts).toEqual([`${aPath}/cancel`, `${bPath}/cancel`]); expect(errors).toEqual([]);
    const geometry = await page.evaluate(() => ({ body: document.body.scrollWidth, document: document.documentElement.scrollWidth }));
    expect(geometry.body).toBeLessThanOrEqual(width); expect(geometry.document).toBeLessThanOrEqual(width);
    await info.attach('requests', { body: JSON.stringify({ posts, reads }), contentType: 'application/json' });
  });
}
