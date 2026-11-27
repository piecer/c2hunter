import { readFileSync } from 'node:fs';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import DDoSAttackPanel from '../src/DDoSAttackPanel';
import * as snapshots from '../src/ddosSourceSnapshot';
import * as contract from '../src/ddosReportContract';

const report = JSON.parse(readFileSync('tests/fixtures/ddos-report-contract.json', 'utf8'));
beforeEach(() => localStorage.setItem('c2hunter-report-language', 'en'));
const controls = [/Show detailed evidence/, /Interpretation scope and caveats/] as const;

it('validates the committed owner transition without validating its discarded render', () => {
  const owned = structuredClone(report);
  const publish = vi.fn();
  const validate = vi.spyOn(contract, 'isDDoSAttackReport');
  const view = render(<DDoSAttackPanel report={owned} setDetailOwner={publish}/>);
  const originalRoot = view.container.querySelector('section.ddos-report');
  validate.mockClear();
  view.rerender(<DDoSAttackPanel report={owned} detailOwner="another-owned-surface" setDetailOwner={publish}/>);
  // One boundary validation, one committed Content validation. The render that
  // synchronizes observedOwner is discarded before children can be committed.
  expect(validate).toHaveBeenCalledTimes(2);
  expect(view.container.querySelector('section.ddos-report') === originalRoot).toBe(true);
  expect(originalRoot).toBeVisible();
});

it.each(controls)('checks live source exactly once before publishing an owner through %s', name => {
  const publish = vi.fn();
  const snapshot = vi.spyOn(snapshots, 'ddosSourceSnapshot');
  render(<DDoSAttackPanel report={structuredClone(report)} setDetailOwner={publish}/>);
  publish.mockClear(); snapshot.mockClear();
  fireEvent.click(screen.getByRole('button', { name }));
  expect(publish).toHaveBeenCalledOnce();
  expect(publish.mock.calls[0][0]).toEqual(expect.any(String));
  expect(snapshot).toHaveBeenCalledOnce();
});

for (const name of controls) it.each(['report', 'extra', 'job', 'unmount'])(`refuses %s changes before captured ${name} disclosure publication`, fault => {
  const owned = structuredClone(report);
  const job = { id: 'owned', dataset_id: 'data' };
  const publish = vi.fn();
  const { unmount } = render(<DDoSAttackPanel report={owned} job={job} setDetailOwner={publish}/>);
  const button = screen.getByRole('button', { name });
  const props = (button as unknown as Record<string, { onClick: () => void }>)[Object.keys(button).find(key => key.startsWith('__reactProps'))!];
  if (fault === 'report') owned.findings[0].metrics.packet_count += 1;
  if (fault === 'extra') owned.unrecognized = true;
  if (fault === 'job') job.dataset_id = 'replacement';
  if (fault === 'unmount') unmount();
  publish.mockClear();
  act(() => props.onClick());
  expect(publish).not.toHaveBeenCalled();
});
