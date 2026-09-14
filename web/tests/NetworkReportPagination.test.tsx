import { openGroups } from './reportDisclosure';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it, vi } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Link, MemoryRouter } from 'react-router-dom';
import App from '../src/App';
import NetworkAnomalyPanel, { type NetworkAnomalyReport } from '../src/NetworkAnomalyPanel';

const python = process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python');
const generate = () => execFileSync(python, ['tests/network_report_fixture.py', '--pagination'], { encoding: 'utf8' });
const bytes = generate();
const fixtures = JSON.parse(bytes) as Record<string, NetworkAnomalyReport>;
beforeEach(() => localStorage.setItem('c2hunter-report-language', 'en'));

it('generates deterministic pagination reports through the real PCAP parser and producer', () => {
  expect(generate()).toBe(bytes);
  for (const n of [0, 8, 9, 20, 23]) {
    expect(fixtures[n].issues).toHaveLength(Math.min(n, 20));
    expect(fixtures[n].summary.issue_count).toBe(n);
    expect(fixtures[n].summary.omitted_issue_count).toBe(Math.max(0, n - 20));
  }
});

it('resets page and detail for replacement reports even with identical counts and IDs, without resetting language', () => {
  const original = fixtures[20];
  const replacement = structuredClone(original);
  replacement.issues![0].first_seen = '2026-09-14T00:00:00Z';
  const { rerender } = render(<NetworkAnomalyPanel report={original}/>);
  openGroups();
  fireEvent.click(screen.getByRole('button', { name: 'Next groups' }));
  fireEvent.click(screen.getAllByRole('button', { name: /Show representative evidence/ })[0]);
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'ko' } });
  rerender(<NetworkAnomalyPanel report={replacement}/>);
  openGroups();
  expect(screen.getByRole('status')).toHaveTextContent('3페이지 중 1페이지');
  expect(screen.getByRole('button', { name: '이전 그룹' })).toBeDisabled();
  expect(screen.queryByRole('region', { name: '대표 흐름 증거' })).not.toBeInTheDocument();
  expect(screen.getByRole('combobox')).toHaveValue('ko');
  // A → B → A must not resurrect A's old page or detail owner.
  rerender(<NetworkAnomalyPanel report={original}/>);
  openGroups();
  expect(screen.getByRole('status')).toHaveTextContent('3페이지 중 1페이지');
  expect(screen.queryByRole('region', { name: '대표 흐름 증거' })).not.toBeInTheDocument();
});

it('resets when the actual job route changes even if cached jobs share the identical report object', async () => {
  localStorage.setItem('c2hunter-token', 'offline-test');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  for (const id of ['page-a', 'page-b']) client.setQueryData(['job', id], { id, name: id, status: 'COMPLETED', analysis: { module: 'network_anomaly' }, network_anomaly: fixtures[20] });
  const fetch = vi.fn<typeof globalThis.fetch>(async () => new Response(JSON.stringify({ items: [] })));
  vi.stubGlobal('fetch', fetch);
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/analyses/page-a']}><Link to="/analyses/page-b">Other job</Link><App/></MemoryRouter></QueryClientProvider>);
  openGroups();
  fireEvent.click(screen.getByRole('button', { name: 'Next groups' }));
  fireEvent.click(screen.getAllByRole('button', { name: /Show representative evidence/ })[0]);
  fireEvent.change(screen.getByRole('combobox', { name: '보고서 언어 / Report language' }), { target: { value: 'ko' } });
  fireEvent.click(screen.getByRole('link', { name: 'Other job' }));
  expect(await screen.findByRole('heading', { name: 'page-b' })).toBeVisible();
  openGroups();
  expect(within(screen.getByRole('navigation', { name: '문제 그룹 페이지' })).getByRole('status')).toHaveTextContent('3페이지 중 1페이지');
  expect(screen.queryByRole('region', { name: '대표 흐름 증거' })).not.toBeInTheDocument();
  expect(screen.getByRole('combobox', { name: '보고서 언어 / Report language' })).toHaveValue('ko');
  expect(fetch.mock.calls.every(([, init]) => (init?.method ?? 'GET') === 'GET')).toBe(true);
});

it.each([0, 8])('does not offer unnecessary pagination for %i retained groups', n => {
  render(<NetworkAnomalyPanel report={fixtures[n]}/>);
  openGroups();
  expect(screen.queryByRole('navigation', { name: 'Issue group pages' })).not.toBeInTheDocument();
  expect(screen.queryAllByRole('article')).toHaveLength(n);
  if (!n) expect(screen.getByText(/No grouped observations retained/)).toBeVisible();
});

it('keeps producer-discarded groups separate from retained groups on other pages in both languages', () => {
  render(<NetworkAnomalyPanel report={fixtures[23]}/>);
  openGroups();
  expect(screen.getByText(/shown on this page/)).toHaveTextContent('12 retained groups not shown on this page');
  expect(screen.getByText(/Report truncated:/)).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Next groups' }));
  fireEvent.click(screen.getByRole('button', { name: 'Next groups' }));
  expect(screen.getByText(/shown on this page/)).toHaveTextContent('4 shown on this page');
  expect(screen.getByText(/shown on this page/)).toHaveTextContent('16 retained groups not shown on this page');
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'ko' } });
  expect(screen.getByRole('status')).toHaveTextContent('3페이지 중 3페이지');
  expect(screen.getByText(/개 현재 페이지에 표시/)).toHaveTextContent('16 개 보존된 그룹 현재 페이지에 표시되지 않음');
  expect(screen.getByRole('button', { name: '다음 그룹' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: '이전 그룹' }));
  expect(screen.getByRole('status')).toHaveTextContent('3페이지 중 2페이지');
});

it('supports Tab, Enter and Space with focus on page status and only live aria-controls targets', async () => {
  const user = userEvent.setup();
  render(<NetworkAnomalyPanel report={fixtures[9]}/>);
  openGroups();
  await user.tab();
  expect(screen.getByRole('combobox')).toHaveFocus();
  await user.tab(); // Coverage disclosure
  await user.tab(); // All groups disclosure
  await user.tab();
  expect(screen.getByRole('button', { name: 'Next groups' })).toHaveFocus();
  await user.keyboard('{Enter}');
  expect(screen.getByRole('status')).toHaveFocus();
  await user.tab(); // Disabled next is skipped; first (last-page) evidence owns focus.
  const evidence = screen.getByRole('button', { name: /Show representative evidence/ });
  expect(evidence).toHaveFocus();
  expect(evidence).not.toHaveAttribute('aria-controls');
  await user.keyboard(' ');
  expect(evidence).toHaveAttribute('aria-expanded', 'true');
  expect(document.getElementById(evidence.getAttribute('aria-controls')!)).toBe(screen.getByRole('region', { name: 'Representative flow evidence' }));
  await user.keyboard('{Enter}');
  expect(evidence).toHaveAttribute('aria-expanded', 'false');
  expect(evidence).toHaveFocus();
  await user.tab({ shift: true });
  expect(screen.getByRole('button', { name: 'Previous groups' })).toHaveFocus();
  await user.keyboard(' ');
  expect(screen.getByRole('status')).toHaveFocus();
  expect(screen.getByRole('status')).toHaveTextContent('Page 1 of 2');
});

it('restores focus to grouped observations when replacement removes the focused last-page article', () => {
  const { rerender } = render(<NetworkAnomalyPanel report={fixtures[20]}/>);
  openGroups();
  fireEvent.click(screen.getByRole('button', { name: 'Next groups' }));
  const evidence = screen.getAllByRole('button', { name: /Show representative evidence/ })[0];
  evidence.focus();
  fireEvent.click(evidence);
  rerender(<NetworkAnomalyPanel report={structuredClone(fixtures[20])}/>);
  expect(screen.getByRole('heading', { name: 'Grouped observations' })).toHaveFocus();
});

it('keeps focus safe when a report replacement removes pagination entirely', () => {
  const { rerender } = render(<NetworkAnomalyPanel report={fixtures[20]}/>);
  openGroups();
  fireEvent.click(screen.getByRole('button', { name: 'Next groups' }));
  expect(screen.getByRole('status')).toHaveFocus();
  rerender(<NetworkAnomalyPanel report={fixtures[0]}/>);
  expect(screen.getByRole('heading', { name: 'Grouped observations' })).toHaveFocus();
  expect(screen.queryByRole('navigation', { name: 'Issue group pages' })).not.toBeInTheDocument();
  expect(screen.queryAllByRole('article')).toHaveLength(0);
  rerender(<NetworkAnomalyPanel report={fixtures[20]}/>);
  openGroups();
  expect(screen.getByRole('status')).toHaveTextContent('Page 1 of 3');
});

it.each([9, 20])('makes every retained group in a %i-group report reachable forward and back', async n => {
  const user = userEvent.setup();
  const report = fixtures[n];
  const { container } = render(<NetworkAnomalyPanel report={report}/>);
  openGroups();
  const previous = screen.getByRole('button', { name: 'Previous groups' });
  const next = screen.getByRole('button', { name: 'Next groups' });
  expect(previous).toBeDisabled();
  expect(next).toBeEnabled();
  const pages = Math.ceil(n / 8);
  for (let page = 0; page < pages; page++) {
    expect(screen.getByRole('status')).toHaveTextContent(`Page ${page + 1} of ${pages}`);
    expect(screen.getAllByRole('article')).toHaveLength(Math.min(8, n - page * 8));
    for (const issue of report.issues!.slice(page * 8, page * 8 + 8)) {
      expect(screen.getByText(new RegExp(issue.scope.sensor_id))).toBeVisible();
    }
    for (const button of screen.getAllByRole('button', { name: /Show representative evidence/ })) {
      await user.click(button);
      expect(screen.getAllByRole('region', { name: 'Representative flow evidence' })).toHaveLength(1);
      expect(container.querySelectorAll('*').length).toBeLessThan(500);
    }
    if (page < pages - 1) {
      await user.click(next);
      expect(screen.queryByRole('region', { name: 'Representative flow evidence' })).not.toBeInTheDocument();
    }
  }
  expect(next).toBeDisabled();
  expect(previous).toBeEnabled();
  for (let page = pages - 2; page >= 0; page--) {
    await user.click(previous);
    expect(screen.getByRole('status')).toHaveTextContent(`Page ${page + 1} of ${pages}`);
    expect(screen.queryByRole('region', { name: 'Representative flow evidence' })).not.toBeInTheDocument();
  }
  expect(previous).toBeDisabled();
  expect(next).toBeEnabled();
});
