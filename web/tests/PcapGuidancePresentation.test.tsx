import { readFileSync, readdirSync } from 'node:fs';
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { expect, it } from 'vitest';
import PcapAttackGuidance from '../src/PcapAttackGuidance';
import ReportLanguageScope from '../src/ReportLanguage';

const fixtures = '../controller/tests/fixtures/pcap_attack_guidance';
const job = (name: string) => JSON.parse(readFileSync(`${fixtures}/${name}.job.json`, 'utf8'));
const view = (value: unknown) => <ReportLanguageScope><PcapAttackGuidance job={value}/></ReportLanguageScope>;
it.each(['en', 'ko'])('explains every producer scenario and renders owned evidence lazily in %s', language => {
  localStorage.setItem('c2hunter-report-language', language);
  for (const name of readdirSync(fixtures).filter(n => n.endsWith('.job.json'))) {
    const value = job(name.replace('.job.json', ''));
    const guide = value.pcap_attack_guidance;
    const { unmount, container } = render(view(value));
    const region = screen.getByRole('region', { name: language === 'en' ? 'PCAP review guidance' : 'PCAP 검토 안내' });
    expect(region).toHaveTextContent(language === 'en' ? 'not malicious-packet labels' : '악성 패킷 라벨이 아닙니다');
    expect(region).toHaveTextContent(language === 'en' ? 'Coverage and omissions' : '관찰 범위와 생략');
    expect(screen.queryByRole('region', { name: /Candidate evidence|후보 근거/ })).not.toBeInTheDocument();
    expect(container.querySelectorAll('a')).toHaveLength(0);
    if (guide.candidates.length) {
      fireEvent.click(within(region).getAllByRole('button', { name: /Review window|검토 구간/ })[0]);
      const evidence = screen.getByRole('region', { name: language === 'en' ? 'Candidate evidence' : '후보 근거' });
      const c = guide.candidates[0];
      for (const label of language === 'en' ? ['Observed evidence', 'Why review this window', 'Caveats', 'Benign alternatives', 'Passive next checks', 'Within-capture baseline'] : ['관찰 근거', '이 구간을 검토하는 이유', '주의 사항', '정상 트래픽의 대안 설명', '수동 후속 확인', '캡처 내 기준선']) expect(within(evidence).getByRole('heading', { name: label })).toBeVisible();
      for (const text of [c.target.ip, c.first_seen, c.last_seen, ...c.source_examples]) expect(evidence).toHaveTextContent(text);
      expect(evidence).toHaveTextContent(language === 'en' ? 'not known-normal traffic' : '정상으로 확인된 트래픽이 아닙니다');
    }
    unmount();
  }
});
it.each(['en', 'ko'])('qualifies temporal replies without claiming completed handshakes in %s', language => {
  localStorage.setItem('c2hunter-report-language', language);
  for (const [name, count] of [['cross_boundary_replies', 0], ['preceding_only_replies', 1]] as const) {
    const value = job(name);
    expect(value.pcap_attack_guidance.candidates).toHaveLength(count);
    const { unmount } = render(view(value));
    expect(screen.getByText(language === 'en' ? /Temporal reply evidence is heuristic/ : /시간순 응답 근거는 휴리스틱/)).toBeVisible();
    expect(screen.getByText(language === 'en' ? /Retained SYN\/SYN-ACK matching observations/ : /보존된 SYN\/SYN-ACK 매칭 관찰/)).toHaveTextContent(String(value.pcap_attack_guidance.summary.response_state_count));
    unmount();
  }
});
it('keeps all 32 candidates reachable in pages of eight with one bounded lazy owner', () => {
  localStorage.setItem('c2hunter-report-language', 'en');
  const value = job('overflow');
  const { container } = render(view(value));
  const initial = document.querySelectorAll('*').length;
  expect(initial).toBeLessThan(300);
  expect(screen.getByText(/Omitted candidates: 224/)).toBeVisible();
  const seen = new Set<string>(); let peak = initial;
  for (let page = 0; page < 4; page++) {
    const buttons = screen.getAllByRole('button', { name: /Review window/ });
    expect(buttons).toHaveLength(8);
    for (let i = 0; i < 8; i++) {
      fireEvent.click(buttons[i]);
      const evidence = screen.getAllByRole('region', { name: 'Candidate evidence' });
      expect(evidence).toHaveLength(1);
      const candidate = value.pcap_attack_guidance.candidates[page * 8 + i];
      expect(evidence[0]).toHaveTextContent(candidate.target.ip);
      seen.add(candidate.target.ip);
      peak = Math.max(peak, document.querySelectorAll('*').length);
      expect(peak).toBeLessThan(450);
    }
    fireEvent.click(buttons[7]);
    expect(screen.queryByRole('region', { name: 'Candidate evidence' })).not.toBeInTheDocument();
    expect(container.querySelectorAll('[hidden]')).toHaveLength(0);
    if (page < 3) fireEvent.click(screen.getByRole('button', { name: 'Next candidate page' }));
  }
  expect(seen.size).toBe(32);
  console.info(JSON.stringify({ guidanceDom: { initial, peak, reached: seen.size } }));
});
it('resets pages and lazy state across cached A→B→A and rejects captured stale callbacks', () => {
  localStorage.setItem('c2hunter-report-language', 'en');
  const a = job('overflow'), b = job('mixed');
  const { rerender } = render(view(a));
  const old = screen.getAllByRole('button', { name: /Review window/ })[0];
  const propsKey = Object.keys(old).find(k => k.startsWith('__reactProps'))!;
  const callback = (old as unknown as Record<string, { onClick: () => void }>)[propsKey].onClick;
  fireEvent.click(old);
  fireEvent.click(screen.getByRole('button', { name: 'Next candidate page' }));
  rerender(view(b));
  expect(screen.queryByRole('region', { name: 'Candidate evidence' })).not.toBeInTheDocument();
  rerender(view(a));
  act(() => callback());
  expect(screen.queryByRole('region', { name: 'Candidate evidence' })).not.toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent('Page 1 of 4');
  fireEvent.click(screen.getAllByRole('button', { name: /Review window/ })[0]);
  expect(screen.getByRole('region', { name: 'Candidate evidence' })).toBeVisible();
  a.pcap_attack_guidance.candidates[0].target.ip = 'poison';
  rerender(view(a));
  expect(screen.getByRole('alert')).toHaveTextContent('Invalid PCAP review guidance');
  expect(screen.queryByRole('region', { name: 'Candidate evidence' })).not.toBeInTheDocument();
  expect(screen.queryByText('poison')).not.toBeInTheDocument();
});
it('distinguishes historical absence, malformed present, and no additional candidate', () => {
  localStorage.setItem('c2hunter-report-language', 'en');
  const value = job('clean_payload');
  const { rerender } = render(view(value));
  expect(screen.getByRole('heading', { name: 'No additional review window retained' })).toBeVisible();
  expect(screen.getByText(/does not cancel existing DDoS findings/)).toBeVisible();
  delete value.pcap_attack_guidance;
  rerender(view(value));
  expect(screen.getByText(/not generated for this job/)).toBeVisible();
  value.pcap_attack_guidance = null;
  rerender(view(value));
  expect(screen.getByRole('alert')).toHaveTextContent('Invalid PCAP review guidance');
  expect(screen.queryByText(/not generated for this job/)).not.toBeInTheDocument();
});
