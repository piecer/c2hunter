import { expect, test } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { installApiFixture } from './route-fixture';

// Real parser/producer output, mocked HTTP transport. Not deployed acceptance.
const python = process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python');
const reports = JSON.parse(execFileSync(python, ['tests/network_report_fixture.py', '--glance'], { encoding: 'utf8' }));

for (const width of [1280, 390]) {
  for (const language of ['ko', 'en']) {
    test(`anomaly overview stays actionable at ${width}px in ${language}`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: 900 });
      const errors: string[] = [];
      const writes: string[] = [];
      page.on('pageerror', error => errors.push(error.message));
      await installApiFixture(page);
      await page.route('**/api/v1/**', async route => {
        const path = new URL(route.request().url()).pathname.replace('/api/v1', '');
        if (route.request().method() !== 'GET' && path !== '/auth/dev-login') writes.push(path);
        let body: unknown;
        if (path === '/analysis-jobs/glance-layout') body = { id: 'glance-layout', name: 'Network anomaly overview', status: 'COMPLETED', analysis: { module: 'network_anomaly' }, network_anomaly: reports.many };
        else if (path === '/analysis-jobs/glance-layout/ai-runs') body = { items: [] };
        else if (path === '/ai-capabilities') body = { available: false, network_interpretation: false, reason: 'Fixture: no inference' };
        else return route.fallback();
        await route.fulfill({ contentType: 'application/json', body: JSON.stringify(body) });
      });
      await page.goto('/login');
      await page.getByLabel('Username').fill('analyst');
      await page.getByRole('button', { name: 'Development login' }).click();
      await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
      await page.goto('/analyses/glance-layout');
      await page.getByLabel('보고서 언어 / Report language').selectOption(language);
      const glance = page.getByRole('region', { name: language === 'ko' ? '한눈에 보기' : 'At a glance', exact: true });
      await expect(glance).toBeVisible();
      await expect(glance.getByTestId('top-observation')).toHaveCount(3);
      await expect(page.locator('.network-report article')).toHaveCount(0);
      const action = page.getByRole('region', { name: language === 'ko' ? '다음 행동' : 'Next action' });
      const actionBox = await action.boundingBox();
      expect(actionBox!.y + actionBox!.height).toBeLessThanOrEqual(900);
      const geometry = await page.evaluate(() => ({ width: innerWidth, body: document.body.scrollWidth, document: document.documentElement.scrollWidth, nodes: document.querySelectorAll('*').length }));
      expect(geometry.body).toBeLessThanOrEqual(width);
      expect(geometry.document).toBeLessThanOrEqual(width);
      expect(geometry.nodes).toBeLessThan(500);
      for (const card of await glance.getByTestId('top-observation').all()) {
        expect(await card.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
      }
      await page.screenshot({ path: testInfo.outputPath('overview.png'), fullPage: true });
      const shortcut = glance.getByRole('button', { name: /근거 확인|Inspect evidence/ }).nth(1);
      await shortcut.focus();
      await page.keyboard.press('Enter');
      const evidence = page.getByRole('region', { name: language === 'ko' ? '대표 흐름 증거' : 'Representative flow evidence', exact: true });
      await expect(evidence).toBeFocused();
      await expect(evidence).toHaveAttribute('id', 'network-evidence-1');
      await expect(page.locator('.network-report article')).toHaveCount(1);
      await page.getByRole('button', { name: language === 'ko' ? '전체 이상 항목 보기' : 'View all anomaly items', exact: true }).click();
      await expect(page.locator('.network-report article')).toHaveCount(8);
      await expect(evidence).toHaveCount(0);
      expect(errors).toEqual([]);
      expect(writes).toEqual([]);
      await testInfo.attach('geometry', { body: JSON.stringify(geometry), contentType: 'application/json' });
    });
  }
}
