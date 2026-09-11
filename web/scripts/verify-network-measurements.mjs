/* global localStorage, innerWidth -- callbacks execute in Chromium */
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
const browser = await chromium.launch({ executablePath: env.C2HUNTER_BROWSER_EXECUTABLE || undefined });
const results = [];
try {
  for (const language of ['en', 'ko']) {
    for (const width of [1280, 390]) {
      const context = await browser.newContext({ viewport: { width, height: 900 } });
      try {
        await context.addInitScript(({ language }) => {
          localStorage.setItem('c2hunter-token', 'offline-browser-fixture');
          localStorage.setItem('c2hunter-report-language', language);
        }, { language });
        const page = await context.newPage();
        const errors = [];
        const requests = [];
        page.on('pageerror', error => errors.push(error.message));
        await page.route('**/*', async route => {
          const request = route.request();
          requests.push({ method: request.method(), url: request.url() });
          const url = new URL(request.url());
          if (url.origin !== 'http://offline-measurements.test') return route.abort();
          if (url.pathname.startsWith('/api/')) {
            const body = url.pathname === '/api/v1/analysis-jobs/measurements' ? { id: 'measurements', name: 'Measurement fixture', status: 'COMPLETED', analysis: { module: 'network_anomaly' }, network_anomaly: fixtures.supporting } : { items: [] };
            return route.fulfill({ contentType: 'application/json', body: JSON.stringify(body) });
          }
          const asset = url.pathname.startsWith('/assets/') ? resolve('dist', `.${url.pathname}`) : resolve('dist/index.html');
          assert(asset.startsWith(resolve('dist') + '/'));
          return route.fulfill({ contentType: asset.endsWith('.js') ? 'text/javascript' : asset.endsWith('.css') ? 'text/css' : 'text/html', body: readFileSync(asset) });
        });
        await page.goto('http://offline-measurements.test/analyses/measurements');
        const cause = page.getByRole('heading', { name: language === 'en' ? 'Possible cause — hypothesis' : '가능한 원인 — 가설', exact: true });
        await cause.waitFor();
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
        assert.deepEqual(errors, []);
        assert(requests.every(request => request.method === 'GET'));
        // Existing saved-AI status/audit reads are permitted; no inference is submitted.
        results.push({ language, width, geometry, errors, requests, noAutomaticAIInference: true, keyboardExpansionAndCollapse: true });
      } finally { await context.close(); }
    }
  }
} finally { await browser.close(); }
writeFileSync(resolve(output, 'RESULTS.json'), JSON.stringify(results, null, 2) + '\n');
stdout.write(JSON.stringify({ verified: results.length, output, results }, null, 2) + '\n');
