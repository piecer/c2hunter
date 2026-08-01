import { expect, test } from '@playwright/test';
import { installApiFixture } from './route-fixture';

test('analyst workflow: login, inspect, analyze, export, allowlist, reanalyze', async ({ page }) => {
  await installApiFixture(page);
  await page.goto('/login');
  await page.getByLabel('Username').fill('analyst');
  await page.getByRole('button', { name: 'Development login' }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
  await expect(page.getByRole('heading', { name: '지금 확인할 항목' })).toBeVisible();
  await expect(page.getByRole('heading', { name: '우선 조사 후보' })).toBeVisible();
  await expect(page.getByRole('link', { name: /203\.0\.113\.10/ }).first()).toBeVisible();

  await page.getByRole('link', { name: 'Sensors', exact: true }).click();
  await page.getByRole('link', { name: 'Sensor A' }).click();
  await expect(page.getByRole('heading', { name: 'Sensor A' })).toBeVisible();

  await page.getByRole('link', { name: 'New analysis' }).click();
  await page.getByLabel('Analysis name').fill('E2E investigation');
  await page.getByLabel('Sensor A').check();
  await page.getByRole('button', { name: 'Start analysis' }).click();
  await expect(page.getByText('ANALYZING')).toBeVisible();
  await page.getByRole('button', { name: 'Cancel analysis' }).click();
  await expect(page.getByText('Cancellation requested')).toBeVisible();

  await page.getByRole('link', { name: 'Candidates' }).click();
  await page.getByRole('link', { name: '203.0.113.10' }).click();
  await expect(page.getByRole('img', { name: 'Traffic over time' })).toBeVisible();
  await expect(page.getByRole('heading', { name: '탐지 근거' })).toBeVisible();
  await expect(page.getByText('주기적 비콘')).toBeVisible();
  await page.setViewportSize({ width: 420, height: 900 });
  const evidenceCard = page.locator('.evidence.detailed').first();
  await expect(evidenceCard).toBeVisible();
  expect(await evidenceCard.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
  await page.getByRole('button', { name: 'Export candidate PCAP' }).click();
  await expect(page.getByText('PCAP export requested')).toBeVisible();
  await page.getByRole('button', { name: 'Reanalyze' }).click();
  await expect(page.getByText('Reanalysis created')).toBeVisible();
  await page.getByRole('button', { name: 'Mark C2 e2e-flow' }).click();
  await page.getByLabel('Analyst note').fill('Manually confirmed C2');
  await page.getByRole('button', { name: 'Save C2 label' }).click();
  await expect(page.getByRole('heading', { name: '탐지 조정 가이드' })).toBeVisible();
  await expect(page.getByText('현재 5점 · 후보 기준 20점 · 15점 부족')).toBeVisible();
  await expect(page.getByText('주기 통신 가중치 조정으로 후보 기준에 도달합니다.')).toBeVisible();

  await page.getByRole('link', { name: 'Allowlist' }).click();
  await page.getByLabel('Value').fill('203.0.113.10');
  await page.getByLabel('Description').fill('Reviewed trusted infrastructure');
  await page.getByRole('button', { name: 'Add entry' }).click();
  await expect(page.getByText('203.0.113.10')).toBeVisible();
  await page.getByRole('button', { name: 'Delete 203.0.113.10' }).click();
  await expect(page.getByText('No allowlist entries')).toBeVisible();
});

test('analyst can manage history and upload an offline PCAP', async ({ page }) => {
  await installApiFixture(page);
  await page.goto('/login');
  await page.getByLabel('Username').fill('analyst');
  await page.getByRole('button', { name: 'Development login' }).click();

  await page.getByRole('link', { name: 'Analysis history' }).click();
  await expect(page.getByRole('table', { name: 'Analysis history' })).toBeVisible();
  await page.getByRole('button', { name: 'Edit E2E investigation' }).click();
  await page.getByLabel('Analyst note').fill('Reviewed in E2E');
  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect(page.getByRole('dialog', { name: 'Edit analysis metadata' })).not.toBeVisible();

  await page.getByRole('link', { name: 'Upload PCAP', exact: true }).first().click();
  await page.getByLabel('Analysis name').fill('Uploaded E2E capture');
  await page.getByLabel('Capture file').setInputFiles({
    name: 'fixture.pcap',
    mimeType: 'application/vnd.tcpdump.pcap',
    buffer: Buffer.from([0xd4, 0xc3, 0xb2, 0xa1]),
  });
  await page.getByRole('button', { name: 'Upload and analyze' }).click();
  await expect(page.getByRole('heading', { name: 'Uploaded E2E capture' })).toBeVisible();
  await expect(page.getByText('PCAP upload')).toBeVisible();
});

test('analyst can combine multiple flow filters and filter-out patterns', async ({ page }) => {
  await installApiFixture(page);
  await page.goto('/login');
  await page.getByLabel('Username').fill('analyst');
  await page.getByRole('button', { name: 'Development login' }).click();
  await page.getByRole('link', { name: 'Analysis history' }).click();
  await page.getByRole('link', { name: 'E2E investigation' }).click();

  await expect(page.getByText('No filter-out patterns configured')).toBeVisible();
  await expect(page.getByText('Filters applied')).toBeVisible();
  await page.getByRole('button', { name: 'Add filter', exact: true }).click();
  await page.getByLabel('Filter 2 protocol').fill('TCP');
  await page.getByRole('button', { name: 'Add filter out' }).click();
  await page.getByRole('button', { name: 'Add filter out' }).click();
  await page.getByLabel('Filter out 1 endpoint IP or CIDR').fill('203.0.113.10');
  await page.getByLabel('Filter out 2 endpoint IP or CIDR').fill('198.51.100.20');

  const filteredRequest = page.waitForRequest(request => {
    const url = new URL(request.url());
    return url.pathname.endsWith('/analysis-jobs/job-1/flows')
      && url.searchParams.getAll('include_filter').length === 2
      && url.searchParams.getAll('exclude_filter').length === 2;
  });
  await page.getByRole('button', { name: 'Apply filters' }).click();
  await filteredRequest;
  await expect(page.getByText('Filters applied')).toBeVisible();

  await page.setViewportSize({ width: 420, height: 900 });
  const filterBuilder = page.locator('.flow-filter-builder');
  expect(await filterBuilder.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
});
