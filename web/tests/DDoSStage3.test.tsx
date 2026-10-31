import { readFileSync } from 'node:fs';
import { fireEvent, render, screen, within } from '@testing-library/react';
import * as exports from '../src/ddosExport';
import { expect, it, vi } from 'vitest';
import DDoSAttackPanel from '../src/DDoSAttackPanel';

const report = JSON.parse(readFileSync('tests/fixtures/ddos-report-contract.json', 'utf8'));
const scenarios = JSON.parse(readFileSync('tests/fixtures/ddos-report-scenarios.json', 'utf8'));
it.each([
  ['tcp_syn_inbound', 'SYN-ACK', 'SYN-ACK'],
  ['tcp_ack_inbound', 'payload', 'payload'],
  ['tcp_rst_inbound', 'middlebox', '중간 장비'],
  ['udp_outbound_participant', 'UDP service', 'UDP 서비스'],
  ['icmp_echo', 'echo requests', 'echo 요청'],
  ['icmp_generic', 'ICMP types', 'ICMP 유형'],
  ['possible_reflection', 'request/response', '요청·응답'],
  ['multi_vector', 'overlapping', '겹치는'],
])('offers passive family-specific checks and reachable secondary responses for %s in both languages', (name, en, ko) => {
  for (const language of ['en', 'ko']) {
    localStorage.setItem('c2hunter-report-language', language);
    const scenario = scenarios[name];
    const primary = scenario.findings.find((item: { id: string }) => item.id === scenario.primary_finding_id);
    const { unmount } = render(<DDoSAttackPanel report={scenario}/>);
    const next = screen.getByRole('region', { name: language === 'en' ? 'Next check' : '다음 확인' });
    expect(next).toHaveTextContent(language === 'en' ? en : ko);
    expect(next).toHaveTextContent(primary.first_seen);
    expect(next).toHaveTextContent(primary.last_seen);
    expect(next).not.toHaveTextContent(/Enable a SYN proxy|Engage upstream scrubbing|Rate-limit nonessential|SYN 프록시.*활성화|스크러빙.*적용|ICMP 속도 제한/);
    fireEvent.click(within(next).getByRole('button'));
    const evidence = screen.getByRole('region', { name: language === 'en' ? 'DDoS finding evidence' : 'DDoS 발견 근거' });
    expect(within(evidence).getByRole('heading', { name: language === 'en' ? 'Uncertainty' : '불확실성' })).toBeVisible();
    expect(within(evidence).getByRole('heading', { name: language === 'en' ? 'Recommended responses' : '권장 대응' })).toBeVisible();
    expect(evidence).toHaveTextContent(language === 'en' ? 'Human approval required' : '운영자 승인 필요');
    unmount();
  }
});
it.each(['en', 'ko'])('distinguishes same-capture low-bucket statistics from operator-selected predicate reference in %s', language => {
  localStorage.setItem('c2hunter-report-language', language);
  render(<DDoSAttackPanel report={report}/>);
  expect(screen.getByText(language === 'en' ? /same-capture low-traffic buckets/ : /같은 캡처의 저트래픽 버킷/)).toBeVisible();
  expect(screen.getByText(language === 'en' ? /operator-selected normal reference.*predicate evaluation.*does not upgrade/ : /운영자가 선택한 정상 참조.*조건식 평가.*상향하지/)).toBeVisible();
});

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
