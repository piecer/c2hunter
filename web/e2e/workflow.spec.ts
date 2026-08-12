import { expect, test } from '@playwright/test';
import { installApiFixture } from './route-fixture';

test('analyst workflow: login, inspect, analyze, export, allowlist, reanalyze', async ({ page }) => {
  await installApiFixture(page);
  await page.goto('/login');
  await page.getByLabel('Username').fill('analyst');
  await page.getByRole('button', { name: 'Development login' }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
  await expect(page.getByRole('heading', { name: '지금 확인할 항목' })).toBeVisible();
  await expect(page.getByRole('heading', { name: '분석 및 조치 필요 후보' })).toBeVisible();
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
  const metricDisclosure = page.locator('.evidence-metric-details').first();
  await expect(metricDisclosure).not.toHaveAttribute('open', '');
  await expect(page.getByText('Timing Window')).not.toBeVisible();
  await metricDisclosure.locator('summary').click();
  await expect(metricDisclosure).toHaveAttribute('open', '');
  await expect(page.getByText('Timing Window')).toBeVisible();
  const nestedScalar = metricDisclosure.locator('.structured-fields dd > span').first();
  await expect(nestedScalar).toBeVisible();
  expect(await nestedScalar.evaluate(element => getComputedStyle(element).display)).not.toBe('grid');
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

test('administrator validates a candidate with TI and exports it to MISP', async ({ page }) => {
  await installApiFixture(page);
  await page.goto('/login');
  await page.getByLabel('Username').fill('admin');
  await page.getByRole('button', { name: 'Development login' }).click();
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
  await page.goto('/candidates/candidate-1');

  await expect(page.getByRole('heading', { name: '판정 및 외부 검증' })).toBeVisible();
  await expect(page.getByText('자동 조회 완료')).toBeVisible();
  await expect(page.getByText('MISP 이벤트 1개')).toBeVisible();
  await expect(page.getByRole('button', { name: 'MISP로 전송' })).toBeDisabled();
  await page.getByLabel('Candidate verdict').selectOption('CONFIRMED_C2');
  await page.getByLabel('Verdict confidence').selectOption('HIGH');
  await page.getByLabel('Verdict note').fill('Beacon and reputation verified');
  await page.getByRole('button', { name: '판정 저장' }).click();
  await expect(page.getByText('확정 C2', { exact: true })).toBeVisible();

  await expect(page.getByRole('heading', { name: '후속 대응 조치' })).toBeVisible();
  await expect(page.locator('.workflow-badge', { hasText: '조치 필요' })).toBeVisible();
  await page.getByLabel('조치 내용').fill('Endpoint isolation started');
  await page.getByRole('button', { name: '조치 시작' }).click();
  await expect(page.locator('.workflow-badge', { hasText: '조치 중' })).toBeVisible();
  await page.getByLabel('조치 내용').fill('Endpoint isolated and IOC blocked');
  await page.getByRole('button', { name: '조치 완료' }).click();
  await expect(page.locator('.workflow-badge', { hasText: '조치 완료' })).toBeVisible();

  await page.getByRole('button', { name: '외부 TI 다시 조회' }).click();
  await expect(page.getByText('악성 8')).toBeVisible();
  await expect(page.getByText('Abuse 신뢰도 91%')).toBeVisible();

  await page.getByLabel('MISP event ID').fill('42');
  await page.getByRole('button', { name: 'MISP로 전송' }).click();
  await expect(page.getByText(/Event 42/)).toBeVisible();
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

test('analyst can download an archived sensor PCAP', async ({ page }) => {
  await installApiFixture(page);
  await page.goto('/login');
  await page.getByLabel('Username').fill('analyst');
  await page.getByRole('button', { name: 'Development login' }).click();

  await page.getByRole('link', { name: 'Sensor PCAPs' }).click();
  await expect(page.getByRole('table', { name: 'Sensor PCAP archives' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'job-1' })).toHaveAttribute('href', '/analyses/job-1');
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Download job-1--eth0-000001.pcap' }).click(),
  ]);
  expect(download.suggestedFilename()).toBe('job-1--eth0-000001.pcap');
});

test('analyst can run bounded AI analysis and inspect the candidate assessment', async ({ page }) => {
  await installApiFixture(page);
  await page.route(/\/api\/v1\/analysis-jobs\/job-1$/, async route => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        id: 'job-1',
        name: 'E2E investigation',
        status: 'COMPLETED',
        progress_percent: 100,
        candidate_count: 1,
      }),
    });
  });
  await page.goto('/login');
  await page.getByLabel('Username').fill('analyst');
  await page.getByRole('button', { name: 'Development login' }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
  await page.goto('/analyses/job-1');

  const aiPanel = page.getByRole('region', { name: 'AI C2 분석' });
  await aiPanel.getByRole('button', { name: 'Run AI analysis' }).click();
  await expect(aiPanel.getByText('COMPLETED')).toBeVisible();
  await expect(aiPanel.getByText('AI LIKELY_C2')).toBeVisible();
  await expect(aiPanel.getByText('E-C2H-001').first()).toBeVisible();
  await expect(aiPanel.getByText('Review priority 72')).toBeVisible();
  await expect(aiPanel.getByText('NEED_MORE_DATA')).toBeVisible();
  await expect(aiPanel.getByText('Splunk hunting SPL')).toBeVisible();
  await expect(aiPanel.getByText(/Not published/)).toBeVisible();
  await expect(aiPanel.getByText(/AI-generated, analyst review required/).first()).toBeVisible();

  await page.getByRole('link', { name: '203.0.113.10' }).click();
  const candidateAI = page.getByRole('region', { name: 'AI C2 판정' });
  await expect(candidateAI.getByText('LIKELY_C2')).toBeVisible();
  await expect(candidateAI.getByText('Stable periodic callback')).toBeVisible();
});

test('analysis configuration is structured and responsive', async ({ page }) => {
  await installApiFixture(page);
  await page.goto('/login');
  await page.getByLabel('Username').fill('analyst');
  await page.getByRole('button', { name: 'Development login' }).click();
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
  await page.goto('/analyses/job-1');

  const configuration = page.getByRole('region', { name: '분석 구성' });
  await expect(configuration).toBeVisible();
  await expect(page.getByRole('region', { name: '탐지 설정 요약' }).getByText('최소 후보 점수')).toBeVisible();
  await expect(page.getByText('60점 이상')).toBeVisible();
  await expect(page.getByText('1.5×')).toBeVisible();
  await expect(page.getByText('강화')).toBeVisible();
  await expect(page.getByText('비활성').first()).toBeVisible();
  await expect(page.getByText('원본 설정 보기')).toBeVisible();
  await expect(page.locator('.raw-config-details')).not.toHaveAttribute('open', '');
  const [pcapDownload] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Download job-1--eth0-000001.pcap' }).click(),
  ]);
  expect(pcapDownload.suggestedFilename()).toBe('job-1--eth0-000001.pcap');

  await page.setViewportSize({ width: 420, height: 900 });
  expect(await configuration.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
  expect(await page.locator('body').evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
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

test('candidate queue exposes workflow status and defaults to latest activity', async ({ page }) => {
  await installApiFixture(page);
  await page.goto('/login');
  await page.getByLabel('Username').fill('analyst');
  await page.getByRole('button', { name: 'Development login' }).click();
  await page.getByRole('link', { name: 'Candidates', exact: true }).click();

  const summary = page.getByRole('region', { name: 'Candidate 처리 현황' });
  await expect(summary.getByText('미분석')).toBeVisible();
  await expect(summary.getByText('분석 중')).toBeVisible();
  await expect(summary.getByText('조치 필요')).toBeVisible();
  await expect(summary.getByText('조치 중')).toBeVisible();
  await expect(summary.getByText('조치 완료')).toBeVisible();
  await expect(summary.getByText('오탐 처리 완료')).toBeVisible();
  await expect(page.getByLabel('Sort candidates')).toHaveValue('-last_seen');
  await expect(page.locator('.workflow-badge', { hasText: '미분석' })).toBeVisible();
});
