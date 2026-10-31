import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';
import { api } from '../src/api';
import { validatePcapGuidanceJob } from '../src/pcapAttackGuidance';

const job = (name: string) => ({ ...JSON.parse(readFileSync(`../controller/tests/fixtures/pcap_attack_guidance/${name}.job.json`, 'utf8')), name: `Review ${name}` });
function open(value: ReturnType<typeof job>) {
  localStorage.setItem('c2hunter-token', 'test'); localStorage.setItem('c2hunter-report-language', 'en');
  vi.spyOn(api, 'get').mockImplementation(async path => path === `/analysis-jobs/${value.id}` ? value : path === '/ai-capabilities' ? { available: false, ddos_interpretation: false } : { items: [] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(['job', value.id], value);
  const result = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/analyses/${value.id}`]}><App/></MemoryRouter></QueryClientProvider>);
  return { ...result, client };
}
it.each(['missing-report', 'wrong-module'])('never hides a present invalid artifact when %s', async kind => {
  const value = job('mixed');
  if (kind === 'missing-report') delete value.ddos_attack;
  else value.analysis.module = 'unknown_module';
  const { unmount, client } = open(value);
  expect(await screen.findByRole('heading', { name: 'Invalid PCAP review guidance' })).toBeVisible();
  expect(screen.queryByText(/not generated for this job/)).not.toBeInTheDocument();
  unmount(); client.clear();
});
it('preserves the actual legacy-positive constant UDP verdict when guidance has no additional window', () => {
  const root = resolve('..');
  const output = spawnSync(resolve(root, '.venv/bin/python'), ['-c', `
import sys, pathlib, hashlib, json
sys.path.insert(0, sys.argv[1])
import pcap_guidance_fixture_builder as b
assert pathlib.Path(b.__file__).resolve() == pathlib.Path(sys.argv[1], 'pcap_guidance_fixture_builder.py').resolve()
content=b.pcap_bytes(b.packets(1200, span_us=10_000_000, protocol=17))
parsed=b.parse_pcap(content,sensor_id='constant-control',internal_networks=['10.0.0.0/8'],retain_network_evidence=True)
j={'id':'constant-udp','dataset_id':'pcap:'+hashlib.sha256(content).hexdigest(),'source_type':'PCAP_UPLOAD','analysis':{'module':'ddos_attack'},'internal_networks':['10.0.0.0/8'],'flow_records':parsed.records,'status':'COMPLETED','name':'Constant UDP control'}
j.update(b.analyze_ddos_job(j)); b.validate_job_guidance(j); del j['flow_records']
print(b.canonical_bytes(j).decode(),end='')
`, resolve(root, 'controller/tests')], { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1', PYTHONPATH: ['controller/src', 'analysis/src', 'shared/src', 'sensor/worker/src'].map(p => resolve(root, p)).join(':') } });
  expect(output.status, output.stderr).toBe(0);
  const value = JSON.parse(output.stdout);
  expect(value.ddos_attack.findings.length).toBeGreaterThan(0);
  expect(['attack_likely', 'suspicious_traffic']).toContain(value.ddos_attack.verdict);
  expect(value.pcap_attack_guidance.status).toBe('NO_CANDIDATE');
  expect(validatePcapGuidanceJob(value).state).toBe('VALID');
  const { unmount, client } = open(value);
  expect(screen.getByRole('heading', { name: /DDoS attack likely|Suspicious DDoS-shaped traffic observed/ })).toBeVisible();
  expect(screen.getByRole('heading', { name: 'No additional review window retained' })).toBeVisible();
  expect(screen.getByText(/does not cancel existing DDoS findings/)).toBeVisible();
  expect(screen.getByText(/Optional AI interprets existing DDoS findings only/)).toBeVisible();
  expect(screen.queryByRole('heading', { name: 'No clear DDoS attack observed' })).not.toBeInTheDocument();
  unmount(); client.clear();
});
it('keeps the integrated maximum job bounded while reaching every guide target', () => {
  const value = job('overflow');
  const { unmount, client } = open(value);
  const reached = new Set<string>();
  const initial = document.querySelectorAll('*').length; let peak = initial;
  for (let page = 0; page < 4; page++) {
    for (const [offset, button] of screen.getAllByRole('button', { name: /Review window/ }).entries()) {
      fireEvent.click(button);
      const evidence = screen.getAllByRole('region', { name: 'Candidate evidence' });
      expect(evidence).toHaveLength(1);
      const ip = value.pcap_attack_guidance.candidates[page * 8 + offset].target.ip;
      expect(evidence[0]).toHaveTextContent(ip); reached.add(ip);
      peak = Math.max(peak, document.querySelectorAll('*').length);
      expect(peak).toBeLessThan(900);
    }
    if (page < 3) fireEvent.click(screen.getByRole('button', { name: 'Next candidate page' }));
  }
  expect(reached.size).toBe(32);
  console.info(JSON.stringify({ integratedGuidanceDom: { initial, peak, reached: reached.size } }));
  unmount(); client.clear();
});
it('uses one detail owner for guide evidence and legacy findings without changing the legacy report', async () => {
  const value = job('positive'), before = JSON.stringify(value.ddos_attack);
  const { unmount, client } = open(value);
  await screen.findByRole('region', { name: 'PCAP review guidance' });
  fireEvent.click(screen.getByRole('button', { name: 'Review window 1' }));
  expect(screen.getByRole('region', { name: 'Candidate evidence' })).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: /Show detailed evidence/ }));
  expect(screen.getByRole('region', { name: 'DDoS finding evidence' })).toBeVisible();
  expect(screen.queryByRole('region', { name: 'Candidate evidence' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Review window 1' }));
  expect(screen.queryByRole('region', { name: 'DDoS finding evidence' })).not.toBeInTheDocument();
  expect(JSON.stringify(value.ddos_attack)).toBe(before);
  expect(within(screen.getByRole('region', { name: 'Candidate evidence' })).queryByRole('link')).not.toBeInTheDocument();
  unmount(); client.clear();
});
it('renders malformed-present rejection alongside the preserved legacy report and accepts a new owner after reanalysis', async () => {
  const value = job('mixed');
  const successor = job('quiet_relative_udp');
  const { unmount, client } = open(value);
  await screen.findByRole('button', { name: 'Review window 1' });
  const post = vi.spyOn(api, 'post').mockResolvedValue(successor);
  client.setQueryData(['job', successor.id], successor);
  fireEvent.click(screen.getByRole('button', { name: 'Review window 1' }));
  const form = screen.getByRole('heading', { name: 'DDoS threshold 재분석' }).closest('form')!;
  fireEvent.submit(form);
  await screen.findByRole('heading', { name: 'Review quiet_relative_udp' });
  expect(post.mock.calls[0][0]).toBe(`/analysis-jobs/${value.id}/reanalyze`);
  expect(post.mock.calls[0][1]).not.toHaveProperty('pcap_attack_guidance');
  expect(screen.queryByRole('region', { name: 'Candidate evidence' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Review window 1' }));
  expect(screen.getByRole('region', { name: 'Candidate evidence' })).toHaveTextContent('600');
  act(() => { client.setQueryData(['job', successor.id], { ...successor, pcap_attack_guidance: value.pcap_attack_guidance }); });
  expect(await screen.findByRole('heading', { name: 'Invalid PCAP review guidance' })).toBeVisible();
  expect(screen.getByRole('region', { name: 'DDoS at a glance' })).toBeVisible();
  expect(screen.queryByRole('region', { name: 'Candidate evidence' })).not.toBeInTheDocument();
  unmount(); client.clear();
});
