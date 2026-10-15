import { readFileSync } from 'node:fs';
import { fireEvent, render, screen, within } from '@testing-library/react';
import * as exports from '../src/ddosExport';
import { expect, it, vi } from 'vitest';
import DDoSAttackPanel from '../src/DDoSAttackPanel';

const report = JSON.parse(readFileSync('tests/fixtures/ddos-report-contract.json', 'utf8'));
it('scopes the three axes to the selected target and leads with patterns and next check', () => {
  render(<DDoSAttackPanel report={report}/>);
  fireEvent.change(screen.getByLabelText('보고서 언어 / Report language'), { target: { value: 'en' } });
  const glance = screen.getByRole('region', { name: 'DDoS at a glance' });
  expect(within(glance).getByText(/Selected target assessment — not a report-wide classification/)).toBeVisible();
  expect(within(glance).getByRole('heading', { name: 'Key observed patterns' })).toBeVisible();
  expect(within(glance).getByRole('heading', { name: 'Next check' })).toBeVisible();
  expect(within(glance).getByText(/Botnet-like is not confirmed botnet/)).toBeVisible();
});
it('mounts only the selected candidate, includes complete denominators and removes it on owner replacement', () => {
  const { rerender } = render(<DDoSAttackPanel report={report}/>);
  fireEvent.change(screen.getByLabelText('보고서 언어 / Report language'), { target: { value: 'en' } });
  fireEvent.click(screen.getByRole('button', { name: /Show detailed evidence/ }));
  expect(screen.queryByText('Evaluated conditions (AND):')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: /Inspect candidate/ }));
  const candidate = screen.getByRole('region', { name: 'Candidate inspection' });
  expect(within(candidate).getByText('Evaluated conditions (AND):')).toBeVisible();
  expect(within(candidate).getByText(/Candidate confidence/)).toHaveTextContent('Low');
  expect(within(candidate).getByText(/Sampled records/)).toBeVisible();
  expect(within(candidate).getByText(/VERIFY_TARGET_OWNERSHIP/)).toBeVisible();
  rerender(<DDoSAttackPanel report={structuredClone(report)}/>);
  expect(screen.queryByRole('region', { name: 'Candidate inspection' })).not.toBeInTheDocument();
});

it('revokes successful downloads and denies captured export callbacks after a cached owner switch without loading', () => {
  const create = vi.fn(() => 'blob:owned'); const revoke = vi.fn();
  vi.stubGlobal('URL', class extends URL { static createObjectURL = create; static revokeObjectURL = revoke; });
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
  const job = { id: 'A', dataset_id: 'dataset-A' };
  const actual = exports.downloadDDoSExport;
  let captured: Parameters<typeof actual> | undefined;
  vi.spyOn(exports, 'downloadDDoSExport').mockImplementation((...args) => { captured = args; return actual(...args); });
  const { rerender } = render(<DDoSAttackPanel report={report} job={job}/>);
  fireEvent.change(screen.getByLabelText('보고서 언어 / Report language'), { target: { value: 'en' } });
  fireEvent.click(screen.getByRole('button', { name: /Show detailed evidence/ }));
  fireEvent.click(screen.getByRole('button', { name: /Inspect candidate/ }));
  fireEvent.click(screen.getByRole('button', { name: 'Download reviewed candidate JSON' }));
  expect(create).toHaveBeenCalledTimes(1); expect(revoke).toHaveBeenCalledWith('blob:owned');
  rerender(<DDoSAttackPanel report={report} job={{ id: 'B', dataset_id: 'dataset-B' }}/>);
  expect(actual(...captured!)).toBe(false);
  expect(create).toHaveBeenCalledTimes(1);
  expect(screen.queryByRole('region', { name: 'Candidate inspection' })).not.toBeInTheDocument();
});
