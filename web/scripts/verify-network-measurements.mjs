/* global localStorage, innerWidth, document -- callbacks execute in Chromium */
// Offline real-browser verification of built UI + actual producer reports.
// npm run build
// C2HUNTER_BROWSER_EXECUTABLE=/path/to/installed/chrome node scripts/verify-network-measurements.mjs /absolute/evidence-directory
// All HTTP requests are intercepted; no live login, controller or AI service is used.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { env, argv, stdout } from 'node:process';
import { URL } from 'node:url';
import { chromium } from '@playwright/test';

const output = resolve(argv[2] ?? '../artifacts/network-measurements-browser');
mkdirSync(output, { recursive: true });
const python = env.C2HUNTER_TEST_PYTHON ?? (existsSync('../.venv/bin/python') ? resolve('../.venv/bin/python') : 'python3');
const fixtures = JSON.parse(execFileSync(python, ['tests/network_report_fixture.py'], { encoding: 'utf8' }));
const paginationFixtures = JSON.parse(execFileSync(python, ['tests/network_report_fixture.py', '--pagination'], { encoding: 'utf8' }));
const glanceFixtures = JSON.parse(execFileSync(python, ['tests/network_report_fixture.py', '--glance'], { encoding: 'utf8' }));
const browser = await chromium.launch({ executablePath: env.C2HUNTER_BROWSER_EXECUTABLE || undefined });
const results = [];
try {
  for (const language of ['en', 'ko']) {
    for (const width of [1280, 390]) {
      const context = await browser.newContext({ viewport: { width, height: 844 } });
      try {
        await context.addInitScript(({ language }) => {
          localStorage.setItem('c2hunter-token', 'offline-browser-fixture');
          localStorage.setItem('c2hunter-report-language', language);
        }, { language });
        const page = await context.newPage();
        const errors = [];
        const requests = [];
        let activeReport = fixtures.supporting;
        page.on('pageerror', error => errors.push(error.message));
        await page.route('**/*', async route => {
          const request = route.request();
          requests.push({ method: request.method(), url: request.url() });
          const url = new URL(request.url());
          if (url.origin !== 'http://offline-measurements.test') return route.abort();
          if (url.pathname.startsWith('/api/')) {
            const body = url.pathname === '/api/v1/analysis-jobs/measurements' ? { id: 'measurements', name: 'Measurement fixture', status: 'COMPLETED', analysis: { module: 'network_anomaly' }, network_anomaly: activeReport } : { items: [] };
            return route.fulfill({ contentType: 'application/json', body: JSON.stringify(body) });
          }
          const asset = url.pathname.startsWith('/assets/') ? resolve('dist', `.${url.pathname}`) : resolve('dist/index.html');
          assert(asset.startsWith(resolve('dist') + '/'));
          return route.fulfill({ contentType: asset.endsWith('.js') ? 'text/javascript' : asset.endsWith('.css') ? 'text/css' : 'text/html', body: readFileSync(asset) });
        });
        await page.goto('http://offline-measurements.test/analyses/measurements');
        const cause = page.getByRole('heading', { name: language === 'en' ? 'Leading possible cause — hypothesis' : '주요 가능한 원인 — 가설', exact: true });
        await cause.waitFor();
        assert.equal(await page.locator('main.content > section.panel:empty').count(), 0, 'completed report must not mount an empty status panel');
        const menu = page.getByRole('button', { name: '메뉴 / Menu', exact: true });
        const primary = page.getByRole('navigation', { name: 'Primary', exact: true });
        if (width === 390) {
          assert(await menu.isVisible());
          assert.equal(await menu.getAttribute('aria-expanded'), 'false');
          assert(!(await primary.isVisible()));
          await menu.focus();
          await page.keyboard.press('Enter');
          assert.equal(await menu.getAttribute('aria-expanded'), 'true');
          assert.equal(await primary.getByRole('link').count(), 12);
          await page.keyboard.press('Tab');
          assert(await primary.getByRole('link', { name: 'Dashboard', exact: true }).evaluate(element => document.activeElement === element));
          await page.keyboard.press('Escape');
          assert.equal(await menu.getAttribute('aria-expanded'), 'false');
          assert(await menu.evaluate(element => document.activeElement === element));
          await page.keyboard.press('Space');
          assert(await page.getByRole('button', { name: 'Sign out', exact: true }).isVisible());
          await primary.getByRole('link', { name: 'Analysis history', exact: true }).focus();
          await page.keyboard.press('Enter');
          assert.equal(await menu.getAttribute('aria-expanded'), 'false');
          assert(await menu.evaluate(element => document.activeElement === element));
          await page.goto('http://offline-measurements.test/analyses/measurements');
          await cause.waitFor();
        } else {
          assert(!(await menu.isVisible()));
          assert(await primary.isVisible());
          assert.equal(await primary.getByRole('link').count(), 12);
        }
        const allGroups = page.getByRole('button', { name: language === 'en' ? 'View all anomaly items' : '전체 이상 항목 보기', exact: true });
        const firstViews = [];
        for (const [scenario, candidate] of Object.entries({ ...fixtures, mixed: glanceFixtures.mixed, many: glanceFixtures.many })) {
          activeReport = candidate;
          await page.reload();
          const glance = page.getByRole('region', { name: language === 'en' ? 'At a glance' : '한눈에 보기', exact: true });
          await glance.waitFor();
          assert.equal(await page.locator('.network-report article').count(), 0);
          assert.equal(await glance.getByTestId('top-observation').count(), Math.min(3, candidate.issues.length));
          assert.equal(await page.getByRole('region', { name: language === 'en' ? 'Supporting measurements' : '보조 측정값' }).count(), 0);
          assert(!(await page.locator('body').innerText()).includes('Pattern scan →'));
          if (!candidate.summary.coverage_complete) assert((await glance.innerText()).includes(language === 'en' ? 'Incomplete or unknown coverage' : '분석 범위가 불완전'));
          const documentDOM = await page.locator('*').count();
          assert(documentDOM < 500);
          const viewportRects = {};
          for (const [key, locator] of Object.entries({ verdict: glance.getByTestId('network-verdict'), firstKeypoint: glance.getByTestId('top-observation').first(), nextCheck: glance.locator('p').filter({ has: page.getByText(language === 'en' ? 'Priority next check' : '우선 확인 사항', { exact: true }) }) })) {
            if (!await locator.count()) continue;
            const rect = await locator.boundingBox();
            viewportRects[key] = rect;
          }
          if (['supporting', 'mixed'].includes(scenario)) {
            assert.deepEqual(Object.keys(viewportRects), ['verdict', 'firstKeypoint', 'nextCheck']);
            assert(await page.locator('body').evaluate(element => element.scrollWidth <= innerWidth), 'no horizontal overflow');
            await page.screenshot({ path: resolve(output, `viewport-${scenario}-${language}-${width}.png`) });
            for (const [key, rect] of Object.entries(viewportRects)) assert(rect && rect.y >= 0 && rect.y + rect.height <= 844, `${language}/${width}/${scenario}/${key}: ${JSON.stringify(rect)}`);
          }
          firstViews.push({ scenario, documentDOM, viewportRects, verdict: await glance.getByTestId('network-verdict').innerText() });
          if (['mixed', 'normal', 'incomplete', 'many'].includes(scenario)) {
            await page.screenshot({ path: resolve(output, `summary-${scenario}-${language}-${width}.png`), fullPage: false });
            writeFileSync(resolve(output, `summary-${scenario}-${language}-${width}.aria.txt`), await glance.ariaSnapshot());
          }
        }
        activeReport = fixtures.supporting;
        await page.reload();
        await allGroups.click();
        const detailName = language === 'en' ? 'Supporting measurements' : '보조 측정값';
        assert.equal(await page.getByRole('region', { name: detailName }).count(), 0);
        const button = page.getByRole('button', { name: language === 'en' ? /Show representative evidence/ : /보기 대표 증거/ });
        await button.focus();
        await page.keyboard.press('Enter');
        const detail = page.getByRole('region', { name: detailName });
        await detail.waitFor();
        assert((await detail.innerText()).includes('100 / 100 / 100'));
        const geometry = await detail.evaluate(element => ({ left: element.getBoundingClientRect().left, right: element.getBoundingClientRect().right, width: innerWidth }));
        assert(geometry.left >= 0 && geometry.right <= geometry.width, JSON.stringify(geometry));
        const snapshot = await page.locator('.network-report').ariaSnapshot();
        assert(snapshot.includes(detailName));
        const name = `measurements-${language}-${width}`;
        await page.screenshot({ path: resolve(output, `${name}.png`), fullPage: true });
        writeFileSync(resolve(output, `${name}.aria.txt`), snapshot);
        await page.keyboard.press('Enter');
        assert.equal(await detail.count(), 0);
        // Reuse the intercepted built-app harness, not a deployed controller.
        activeReport = paginationFixtures['23'];
        assert.equal(activeReport.issues.length, 20);
        assert.equal(activeReport.summary.omitted_issue_count, 3);
        await page.reload();
        const report = page.locator('.network-report');
        const previous = report.getByRole('button', { name: language === 'en' ? 'Previous groups' : '이전 그룹', exact: true });
        const next = report.getByRole('button', { name: language === 'en' ? 'Next groups' : '다음 그룹', exact: true });
        await allGroups.click();
        await next.waitFor();
        assert(await previous.isDisabled());
        let peakReportDOM = 0;
        let peakDocumentDOM = 0;
        const evidenceName = language === 'en' ? 'Representative flow evidence' : '대표 흐름 증거';
        for (let current = 0; current < 3; current++) {
          assert.equal(await report.getByRole('article').count(), current === 2 ? 4 : 8);
          assert.equal(await report.getByRole('region', { name: evidenceName, exact: true }).count(), 0);
          for (let index = 0; index < (current === 2 ? 4 : 8); index++) {
            const evidenceButton = report.getByRole('article').nth(index).getByRole('button');
            await evidenceButton.focus();
            await page.keyboard.press(index % 2 ? 'Space' : 'Enter');
            assert.equal(await report.getByRole('region', { name: evidenceName, exact: true }).count(), 1);
            assert(await evidenceButton.evaluate(element => document.activeElement === element && document.getElementById(element.getAttribute('aria-controls')) !== null));
            peakReportDOM = Math.max(peakReportDOM, await report.locator('*').count());
            peakDocumentDOM = Math.max(peakDocumentDOM, await page.locator('*').count());
            assert(peakReportDOM < 500);
            assert(peakDocumentDOM < 500);
          }
          if (current < 2) {
            await next.focus();
            await page.keyboard.press('Enter');
            assert(await report.getByRole('status').evaluate(element => document.activeElement === element));
          }
        }
        assert((await report.innerText()).includes(activeReport.issues.at(-1).scope.sensor_id));
        assert(await next.isDisabled());
        assert(!(await previous.isDisabled()));
        const paginationSnapshot = await report.ariaSnapshot();
        assert(paginationSnapshot.includes(language === 'en' ? 'Page 3 of 3' : '3페이지 중 3페이지'));
        await page.screenshot({ path: resolve(output, `pagination-${language}-${width}.png`), fullPage: true });
        writeFileSync(resolve(output, `pagination-${language}-${width}.aria.txt`), paginationSnapshot);
        for (let current = 1; current >= 0; current--) {
          await previous.focus();
          await page.keyboard.press('Space');
          assert(await report.getByRole('status').evaluate(element => document.activeElement === element));
          assert.equal(await report.getByRole('region', { name: evidenceName, exact: true }).count(), 0);
        }
        assert(await previous.isDisabled());
        assert(!(await next.isDisabled()));
        // Tab skips the disabled previous control; next and evidence remain native.
        await page.keyboard.press('Tab');
        assert(await next.evaluate(element => document.activeElement === element));
        activeReport = glanceFixtures.many;
        await page.reload();
        await allGroups.click();
        let threeExamplePeak = 0;
        for (let current = 0; current < 3; current++) {
          const articles = report.getByRole('article');
          for (let index = 0; index < await articles.count(); index++) {
            const evidence = articles.nth(index).getByRole('button');
            await evidence.focus();
            await page.keyboard.press(index % 2 ? 'Space' : 'Enter');
            assert.equal(await page.getByRole('region', { name: detailName, exact: true }).count(), 3);
            threeExamplePeak = Math.max(threeExamplePeak, await page.locator('*').count());
            assert(threeExamplePeak < 500);
          }
          if (current < 2) await next.click();
        }
        await page.screenshot({ path: resolve(output, `three-examples-${language}-${width}.png`), fullPage: true });
        assert.deepEqual(errors, []);
        assert(requests.every(request => request.method === 'GET'));
        // Existing saved-AI status/audit reads are permitted; no inference is submitted.
        results.push({ language, width, firstViews, threeExamplePeak, geometry, errors, requests, noAutomaticAIInference: true, keyboardExpansionAndCollapse: true, pagination: { producerGroups: 23, retainedGroups: 20, producerOmitted: 3, visitedGroups: 20, lastPageAccessible: true, keyboardForwardAndBack: true, peakReportDOM, peakDocumentDOM } });
      } finally { await context.close(); }
    }
  }
} finally { await browser.close(); }
writeFileSync(resolve(output, 'RESULTS.json'), JSON.stringify(results, null, 2) + '\n');
stdout.write(JSON.stringify({ verified: results.length, output, results }, null, 2) + '\n');
