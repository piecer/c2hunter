import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';
import { api } from '../src/api';

const ddos = { ddos_bucket_seconds: 1, ddos_min_duration_seconds: 3, ddos_min_source_count: 20, ddos_min_packet_count: 1000, ddos_min_packets_per_second: 100, ddos_min_bits_per_second: 1000000, ddos_baseline_min_buckets: 20, ddos_baseline_ratio: 5, ddos_mad_z_threshold: 6, ddos_protocol_share_threshold: 0.8, ddos_tcp_flag_share_threshold: 0.8, ddos_response_ratio_max: 0.2, ddos_reflection_port_share_threshold: 0.6, ddos_reflection_min_average_packet_bytes: 256, ddos_overlap_window_seconds: 10 };
const weights = { common_destination: 1, non_well_known_port: 1, periodic_beacon: 0.5, single_host_composite_beacon: 1, analyst_payload_signature: 1, synchronized_communication: 1, command_attack_correlation: 1, persistence_rarity: 1, protocol_similarity: 1, multi_sensor_context: 1, ml_population_anomaly: 1, tcp_session_quality: 1 };
function mount(route: string) {
  localStorage.setItem('c2hunter-token', 'stage5');
  localStorage.setItem('c2hunter-report-language', 'en');
  vi.spyOn(api, 'get').mockImplementation(async path => {
    if (path === '/sensors') return { items: [{ sensor_id: 'sensor-A', name: 'Sensor A' }] };
    if (path === '/detector-weight-presets') return { items: [{ id: 'default', name: 'Default', is_default: true, detector_weights: weights }] };
    if (path.startsWith('/analysis-jobs?')) return { items: [{ id: 'normal-job', dataset_id: 'normal-data', name: 'Normal capture', status: 'COMPLETED' }], total: 1, page: 1, page_size: 20 };
    throw new Error(`Unexpected read ${path}`);
  });
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={[route]}><App/></MemoryRouter></QueryClientProvider>);
}
function disclosure() { return screen.getByText('Advanced options / 고급 설정'); }
function toggle() { fireEvent.click(disclosure()); }
function change(label: string, value: string) { fireEvent.change(screen.getByLabelText(label), { target: { value } }); }

for (const upload of [true, false]) for (const module of ['c2', 'network_anomaly', 'ddos_attack']) it(`${upload ? 'Upload' : 'New'} ${module} keeps exact default and edited wire intent through disclosure`, async () => {
  const post = vi.spyOn(api, 'post').mockRejectedValue(new Error('Retained admission failure'));
  mount(upload ? '/analyses/upload' : '/analyses/new');
  change('Analysis name', 'Stage5 input');
  if (!upload) fireEvent.click(await screen.findByRole('checkbox', { name: 'Sensor A' }));
  if (module === 'c2') await waitFor(() => expect(screen.getByLabelText('저장된 탐지 가중치 프리셋')).toHaveValue('default'));
  change('Analysis module', module);
  const file = new File(['pcap'], 'test.pcap');
  if (upload) fireEvent.change(screen.getByLabelText('Capture file'), { target: { files: [file] } });
  const form = screen.getByLabelText('Analysis name').closest('form')!;
  const advanced = disclosure().closest('details')!;
  expect(advanced).not.toHaveAttribute('open');
  expect(screen.getByRole('status', { name: 'Submission phase' })).toHaveTextContent('입력 준비');
  expect(screen.getByText('Next: 필수 입력을 확인한 뒤 분석을 시작하세요.')).toBeVisible();
  expect(screen.getByRole('button', { name: upload ? 'Upload and analyze' : 'Start analysis' }).compareDocumentPosition(advanced) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  const defaults = Object.fromEntries(new FormData(form));
  toggle(); toggle(); toggle();
  expect(Object.fromEntries(new FormData(form))).toEqual(defaults);
  expect(post).not.toHaveBeenCalled();
  toggle();
  fireEvent.submit(form);
  await screen.findByText('Retained admission failure');
  const analysis = module === 'c2' ? { module, profile: 'ddos_botnet', minimum_candidate_score: upload ? 0 : 50, minimum_distinct_clients: 3, ...(upload ? { periodicity_min_samples: 5 } : {}), ml_anomaly_enabled: false, ml_anomaly_allow_standalone: false } : { module, ...(module === 'ddos_attack' ? ddos : {}) };
  const base = { name: 'Stage5 input', idempotency_key: expect.any(String), internal_networks: upload ? ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'] : ['10.0.0.0/8'], analysis, ...(module === 'ddos_attack' ? { ddos_normal_reference: null } : {}) };
  const expected = upload ? { ...base, description: '', filename: 'test.pcap', analysis_module: module } : { ...base, sensor_ids: ['sensor-A'], mode: 'LIVE', start_time: expect.any(String), end_time: expect.any(String), capture: { duration_seconds: 300, max_packets: 2000000, directions: ['INBOUND', 'OUTBOUND'], bpf_filter: 'ip', store_pcap: true } };
  expect(post.mock.calls[0]).toEqual([upload ? '/pcap-analysis-jobs/initiate' : '/analysis-jobs', expected]);
  toggle();
  change(upload && module === 'ddos_attack' ? 'Protected-side networks' : 'Internal networks', '192.0.2.0/24');
  if (upload) change('Analyst note', 'Retained note');
  else { change('Maximum packets', '1234'); change('BPF filter', 'tcp'); fireEvent.click(screen.getByLabelText('OUTBOUND')); fireEvent.click(screen.getByLabelText('Store PCAP')); }
  if (module === 'c2') {
    change('Minimum score', '0');
    fireEvent.click(screen.getByLabelText('후보군 대비 이상 통신 탐지 사용'));
    fireEvent.change(screen.getAllByRole('spinbutton', { name: / 가중치$/ })[0], { target: { value: '0' } });
  }
  if (module === 'ddos_attack') {
    change('Maximum SYN response ratio', '0');
    change('Normal reference action', 'select');
    fireEvent.click(await screen.findByRole('radio'));
  }
  const edited = Object.fromEntries(new FormData(form));
  toggle(); toggle();
  expect(Object.fromEntries(new FormData(form))).toEqual(edited);
  toggle();
  fireEvent.submit(form);
  await waitFor(() => expect(post).toHaveBeenCalledTimes(2));
  await screen.findByText('Retained admission failure');
  const expectedEdited = { ...expected, internal_networks: ['192.0.2.0/24'], ...(upload ? { description: 'Retained note' } : { capture: { duration_seconds: 300, max_packets: 1234, directions: ['INBOUND'], bpf_filter: 'tcp', store_pcap: false } }), ...(module === 'ddos_attack' ? { ddos_normal_reference: { job_id: 'normal-job', dataset_id: 'normal-data' } } : {}), analysis: { ...analysis, ...(module === 'c2' ? { minimum_candidate_score: 0, ml_anomaly_enabled: true, detector_weights: { ...weights, common_destination: 0 } } : module === 'ddos_attack' ? { ddos_response_ratio_max: 0 } : {}) } };
  expect(post.mock.calls[1]).toEqual([upload ? '/pcap-analysis-jobs/initiate' : '/analysis-jobs', expectedEdited]);
});

it.each(['c2', 'network_anomaly', 'ddos_attack'])('New %s disclosure preserves a pending submission and refuses duplicate admission', async module => {
  let reject!: (error: Error) => void;
  const post = vi.spyOn(api, 'post').mockImplementation(() => new Promise((_, fail) => { reject = fail; }));
  mount('/analyses/new');
  fireEvent.click(await screen.findByRole('checkbox', { name: 'Sensor A' }));
  change('Analysis name', 'Pending new analysis');
  change('Analysis module', module);
  const form = screen.getByLabelText('Analysis name').closest('form')!;
  fireEvent.submit(form);
  await waitFor(() => expect(post).toHaveBeenCalledTimes(1));
  const body = post.mock.calls[0][1];
  toggle(); toggle(); toggle(); toggle();
  expect(screen.getByRole('status', { name: 'Submission phase' })).toHaveTextContent('요청 중 · 서버 수락 확인 대기');
  expect(screen.getByRole('button', { name: 'Starting…' })).toBeDisabled();
  fireEvent.submit(form);
  expect(post).toHaveBeenCalledTimes(1);
  await act(async () => reject(new Error('Unconfirmed admission')));
  await screen.findByText('Unconfirmed admission');
  expect(screen.getByRole('status', { name: 'Submission phase' })).toHaveTextContent('Next: 오류와 기존 작업 상태를 확인한 뒤 재시도하세요.');
  expect(post).toHaveBeenCalledTimes(1);
  if (module === 'ddos_attack') {
    fireEvent.submit(form);
    await waitFor(() => expect(post).toHaveBeenCalledTimes(2));
    expect(post.mock.calls[1][1]).toBe(body);
    await act(async () => reject(new Error('Unconfirmed admission')));
    await screen.findByText('Unconfirmed admission');
  }
});

it('disclosure does not retire an admitted upload, alter its file, or turn sent bytes into server acceptance', async () => {
  const post = vi.spyOn(api, 'post').mockResolvedValue({ id: 'owner-A' });
  let reject!: (error: Error) => void;
  const put = vi.spyOn(api, 'uploadWithProgress').mockImplementation(() => new Promise((_, fail) => { reject = fail; }));
  mount('/analyses/upload');
  await waitFor(() => expect(screen.getByLabelText('저장된 탐지 가중치 프리셋')).toHaveValue('default'));
  change('Analysis name', 'Pending capture');
  const file = new File(['pcap'], 'test.pcap');
  fireEvent.change(screen.getByLabelText('Capture file'), { target: { files: [file] } });
  fireEvent.submit(screen.getByLabelText('Analysis name').closest('form')!);
  await waitFor(() => expect(put).toHaveBeenCalledTimes(1));
  toggle(); toggle();
  await act(async () => { put.mock.calls[0][3]!({ loaded: 4, total: 4 }); });
  expect(screen.getByText('전송 완료 · 서버 저장 확인 중')).toBeVisible();
  expect(screen.getByRole('button', { name: 'Uploading and analyzing…' })).toBeDisabled();
  await act(async () => reject(new Error('Capture not accepted')));
  await screen.findByText('Capture not accepted');
  expect(screen.getByRole('status', { name: 'Submission phase' })).toHaveTextContent('요청 실패 · 수락 여부 확인 필요');
  expect(screen.getByRole('status', { name: 'Submission phase' })).not.toHaveTextContent('서버 저장 확인 중');
  toggle(); toggle();
  put.mockRejectedValue(new Error('Capture not accepted'));
  fireEvent.click(screen.getByRole('button', { name: '기존 작업으로 업로드 재시도' }));
  await waitFor(() => expect(put).toHaveBeenCalledTimes(2));
  expect(post).toHaveBeenCalledTimes(1);
  for (const call of put.mock.calls) { expect(call[0]).toBe('/pcap-analysis-jobs/owner-A/capture'); expect(call[1]).toBe(file); }
  await screen.findByText('Capture not accepted');
});
