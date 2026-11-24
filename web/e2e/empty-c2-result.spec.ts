import { withLegacyAuthentication } from './auth-fixture';
import { test, expect } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const C = fileURLToPath(new URL('../../', import.meta.url));
const wire = execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? C + '/.venv/bin/python', ['-I', '-B', C + '/web/tests/stage6_empty_c2_producer.py'], { encoding: 'utf8', timeout: 30000 });
const producer = JSON.parse(wire), job = JSON.parse(producer.job_wire);
for (const width of [1280, 390])
    for (const language of ['en', 'ko'])
        test(`actual empty C2 result not safety verdict first fold ${width} ${language}`, async ({ page }, info) => {
            const requests: {
                method: string;
                url: string;
            }[] = [], errors: string[] = [], consoleMessages: {
                type: string;
                text: string;
            }[] = [];
            page.on('request', r => requests.push({ method: r.method(), url: r.url() }));
            page.on('pageerror', e => errors.push(e.message));
            page.on('console', m => consoleMessages.push({ type: m.type(), text: m.text() }));
            await page.setViewportSize({ width, height: 900 });
            await page.addInitScript(lang => { localStorage.setItem('c2hunter-token', 'test'); localStorage.setItem('c2hunter-report-language', lang); }, language);
            await page.route('**/api/v1/**', withLegacyAuthentication(r => {
                if (r.request().method() !== 'GET') return r.abort();
                const path = new URL(r.request().url()).pathname;
                const detailPath = '/api/v1/analysis-jobs/' + job.id;
                if (path === detailPath) return r.fulfill({ contentType: 'application/json', body: producer.job_wire });
                if (path === detailPath + '/candidates') return r.fulfill({ contentType: 'application/json', body: producer.candidates_wire });
                return r.fulfill({ status: 404, json: { error: { code: 'FIXTURE_ROUTE_MISSING', message: path } } });
            }));
            try {
                await page.goto('/analyses/' + job.id);
                const summary = page.getByRole('region', { name: language === 'en' ? 'C2 result summary' : 'C2 결과 요약', exact: true });
                const verdict = summary.getByRole('heading', { name: language === 'en' ? '0 retained candidates · Not a safety verdict' : '보존된 탐지 후보 0건 · 안전 판정 아님', exact: true });
                await expect(verdict).toBeVisible();
                const next = summary.getByRole('button', { name: language === 'en' ? 'Review candidates' : '후보 검토로 이동', exact: true });
                const bounds = [];
                for (const target of [verdict, next, summary.getByText(language === 'en' ? 'Retained candidates only, not a safety verdict for all traffic. AI execution and analyst workflow are separate.' : '보존된 후보 범위이며 전체 트래픽의 안전 판정이 아닙니다. AI 실행 여부와 분석가 처리 상태는 별개입니다.', { exact: true })]) {
                    const b = await target.boundingBox();
                    bounds.push(b);
                    expect(b!.y).toBeGreaterThanOrEqual(0);
                    expect(b!.y + b!.height).toBeLessThanOrEqual(900);
                }
                await expect(summary.locator('.c2-key-facts > li')).toHaveCount(4);
                expect(await summary.evaluate(el => Boolean(el.compareDocumentPosition(document.querySelector('.c2-purpose-nav')!) & Node.DOCUMENT_POSITION_FOLLOWING))).toBe(true);
                const geometry = await page.evaluate(() => ({ nodes: document.querySelectorAll('*').length, body: document.body.scrollWidth, document: document.documentElement.scrollWidth }));
                expect(geometry.nodes).toBeLessThanOrEqual(1200);
                expect(geometry.body).toBeLessThanOrEqual(width);
                expect(geometry.document).toBeLessThanOrEqual(width);
                await page.screenshot({ path: info.outputPath('empty-result-firstfold.png') });
                await next.focus();
                await page.keyboard.press('Enter');
                await expect(page.getByRole('heading', { name: language === 'en' ? 'Detected candidates' : '탐지 후보', exact: true })).toBeFocused();
                expect(requests.filter(r => r.url.includes('/api/v1/')).map(r => new URL(r.url).pathname)).toEqual(['/api/v1/auth/csrf', '/api/v1/auth/me', '/api/v1/analysis-jobs/' + job.id, '/api/v1/analysis-jobs/' + job.id + '/candidates']);
                await info.attach('bounds', { body: JSON.stringify({ bounds, geometry }), contentType: 'application/json' });
            }
            finally {
                await info.attach('producer-wire', { body: wire, contentType: 'application/json' });
                await info.attach('observations', { body: JSON.stringify({ requests, errors, console: consoleMessages }), contentType: 'application/json' });
                expect(errors).toEqual([]);
                expect(consoleMessages.filter(m => m.type === 'error')).toEqual([]);
                expect(requests.filter(r => r.method !== 'GET')).toEqual([]);
            }
        });
