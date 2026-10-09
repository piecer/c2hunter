import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { expect, it, vi } from 'vitest';
import C2DiscoverySelection from '../src/C2DiscoverySelection';
import C2AssessmentDetails from '../src/C2AssessmentDetails';
import ReportLanguageScope from '../src/ReportLanguage';

it('renders exact real API selection and evidence bytes for a rule-free candidate', async () => {
  const python = process.env.C2HUNTER_TEST_PYTHON ?? (existsSync('../.venv/bin/python') ? resolve('../.venv/bin/python') : 'python3');
  const wire = JSON.parse(execFileSync(python, ['tests/c2_discovery_fixture.py'], { encoding: 'utf8', timeout: 30000 }));
  const run = JSON.parse(wire.run_bytes);
  const selection = JSON.parse(wire.selection_bytes);
  const assessment = JSON.parse(wire.assessment_bytes).items[0];
  expect(run.selection_summary.rule_free_selected_count).toBe(1);
  expect(assessment.external_ip).toBe(wire.target);
  expect(selection.items.find((item: { external_ip: string }) => item.external_ip === wire.target).origin).toBe('BEHAVIOR');
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    expect(String(input)).toBe(`/api/v1/ai-runs/${run.id}/selection?offset=0&limit=20`);
    return new Response(wire.selection_bytes, { headers: { 'content-type': 'application/json' } });
  }));
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><ReportLanguageScope>
    <C2DiscoverySelection runId={run.id} summary={run.selection_summary}/>
    <C2AssessmentDetails item={assessment}/>
  </ReportLanguageScope></QueryClientProvider>);
  const user = userEvent.setup();
  await user.click(screen.getByRole('button', { name: '선택 목록 보기' }));
  expect(await screen.findByText(wire.target)).toBeInTheDocument();
  expect(screen.getByText('DISCOVERY_RESERVED')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: '저장된 증거 보기' }));
  const facts = screen.getByRole('region', { name: '관찰된 사실' });
  expect(within(facts).getByText(/BEHAVIOR_RELATIVE_RECURRENCE/)).toBeInTheDocument();
  expect(within(facts).getByText(/BEHAVIOR_RELATIVE_RECORD_SIZE_STABILITY/)).toBeInTheDocument();
  expect(within(facts).getByText(/scheduled benign traffic is an alternative/)).toBeInTheDocument();
  expect(screen.getByText(/미선택은 안전하다는 뜻이 아닙니다/)).toBeInTheDocument();
}, 35000);
