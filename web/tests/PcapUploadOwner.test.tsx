import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';
import { api } from '../src/api';

async function uploadForm(module = 'ddos_attack', defaultPreset = false) {
  localStorage.setItem('c2hunter-token', 'owned-test');
  localStorage.setItem('c2hunter-report-language', 'en');
  vi.stubGlobal('fetch', vi.fn(async (url: string) => Response.json(url.includes('detector-weight-presets') ? { items: defaultPreset ? [{ id: 'default', name: 'Default preset', is_default: true, detector_weights: { periodic_beacon: 0.5 } }] : [] } : { items: [{ id: 'normal', dataset_id: 'normal-data', name: 'Normal', status: 'COMPLETED' }], total: 1 })));
  const view = render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/analyses/upload']}><App/></MemoryRouter></QueryClientProvider>);
  fireEvent.change(screen.getByLabelText('Analysis name'), { target: { value: 'Owned upload' } });
  fireEvent.change(screen.getByLabelText('Analysis module'), { target: { value: module } });
  const file = new File(['pcap'], 'owned.pcap');
  fireEvent.change(screen.getByLabelText('Capture file'), { target: { files: [file] } });
  return { ...view, file, form: screen.getByLabelText('Analysis name').closest('form')! };
}

it.each(['c2', 'network_anomaly'])('never uploads to the admitted DDoS/normal owner after selecting %s', async module => {
  const post = vi.spyOn(api, 'post').mockResolvedValueOnce({ id: 'admitted-ddos' }).mockResolvedValueOnce({ id: 'admitted-current' });
  const put = vi.spyOn(api, 'uploadWithProgress').mockRejectedValue(new Error('Owned capture interruption'));
  const { form } = await uploadForm();
  fireEvent.change(screen.getByLabelText('Normal reference action'), { target: { value: 'select' } });
  fireEvent.click(await screen.findByRole('radio'));
  fireEvent.submit(form);
  await screen.findByText('Owned capture interruption');
  expect(post).toHaveBeenCalledTimes(1);
  expect(post.mock.calls[0][1]).toHaveProperty('ddos_normal_reference', { job_id: 'normal', dataset_id: 'normal-data' });
  fireEvent.change(screen.getByLabelText('Analysis module'), { target: { value: module } });
  fireEvent.submit(form);
  await waitFor(() => expect(put).toHaveBeenCalledTimes(2));
  expect(post, 'changed module must acquire a matching job').toHaveBeenCalledTimes(2);
  expect(post.mock.calls[1][1]).toHaveProperty('analysis_module', module);
  expect(post.mock.calls[1][1]).not.toHaveProperty('ddos_normal_reference');
  expect(put.mock.calls[1][0]).toBe('/pcap-analysis-jobs/admitted-current/capture');
});

it('retires before a scheduled mutation can dispatch its admission', async () => {
  const post = vi.spyOn(api, 'post').mockResolvedValue({ id: 'retired' });
  const put = vi.spyOn(api, 'uploadWithProgress').mockRejectedValue(new Error('Must not upload'));
  const { form } = await uploadForm('c2');
  await act(async () => {
    fireEvent.submit(form);
    fireEvent.change(screen.getByLabelText('Analysis module'), { target: { value: 'network_anomaly' } });
  });
  expect(post).not.toHaveBeenCalled();
  expect(put).not.toHaveBeenCalled();
  expect(screen.getByRole('button', { name: 'Upload and analyze' })).toBeEnabled();
});

it.each(['ddos_attack', 'c2', 'network_anomaly'])('same-intent ordinary and explicit retries reuse exactly the admitted %s job and file', async module => {
  const post = vi.spyOn(api, 'post').mockResolvedValue({ id: 'admitted-A' });
  const put = vi.spyOn(api, 'uploadWithProgress').mockRejectedValue(new Error('Owned capture interruption'));
  const { form, file } = await uploadForm(module);
  fireEvent.submit(form);
  await screen.findByText('Owned capture interruption');
  const body = post.mock.calls[0][1];
  fireEvent.submit(form);
  await waitFor(() => expect(put).toHaveBeenCalledTimes(2));
  await screen.findByText('Owned capture interruption');
  fireEvent.click(screen.getByRole('button', { name: '기존 작업으로 업로드 재시도' }));
  await waitFor(() => expect(put).toHaveBeenCalledTimes(3));
  await screen.findByText('Owned capture interruption');
  expect(post).toHaveBeenCalledTimes(1);
  expect(post.mock.calls[0][1]).toBe(body);
  expect(Object.isFrozen(body)).toBe(true);
  for (const call of put.mock.calls) {
    expect(call[0]).toBe('/pcap-analysis-jobs/admitted-A/capture');
    expect(call[1]).toBe(file);
  }
});

it.each([['c2', 'ddos_attack'], ['network_anomaly', 'ddos_attack'], ['c2', 'network_anomaly'], ['network_anomaly', 'c2']])('binds the successor %s -> %s to its actual module', async (from, to) => {
  const post = vi.spyOn(api, 'post').mockResolvedValueOnce({ id: 'A' }).mockResolvedValueOnce({ id: 'B' });
  const put = vi.spyOn(api, 'uploadWithProgress').mockRejectedValue(new Error('Owned capture interruption'));
  const { form } = await uploadForm(from);
  fireEvent.submit(form);
  await screen.findByText('Owned capture interruption');
  fireEvent.change(screen.getByLabelText('Analysis module'), { target: { value: to } });
  fireEvent.submit(form);
  await waitFor(() => expect(put).toHaveBeenCalledTimes(2));
  await screen.findByText('Owned capture interruption');
  expect(post).toHaveBeenCalledTimes(2);
  expect(post.mock.calls[1][1]).toMatchObject({ analysis_module: to, analysis: { module: to } });
  expect(put.mock.calls[1][0]).toBe('/pcap-analysis-jobs/B/capture');
});

it.each(['file', 'same-metadata-file', 'networks', 'threshold', 'weights', 'preset-button'])('retires an admission when the wire intent/file changes: %s', async change => {
  const post = vi.spyOn(api, 'post').mockResolvedValueOnce({ id: 'A' }).mockResolvedValueOnce({ id: 'B' });
  const put = vi.spyOn(api, 'uploadWithProgress').mockRejectedValue(new Error('Owned capture interruption'));
  const { form, file } = await uploadForm('c2');
  fireEvent.submit(form);
  await screen.findByText('Owned capture interruption');
  if (change.endsWith('file')) {
    const next = new File(['PCAP'], change === 'file' ? 'other.pcap' : file.name);
    expect(next).not.toBe(file);
    expect(next.size).toBe(file.size);
    fireEvent.change(screen.getByLabelText('Capture file'), { target: { files: [next] } });
  } else if (change === 'networks') fireEvent.change(screen.getByLabelText('Internal networks'), { target: { value: '192.0.2.0/24' } });
  else if (change === 'threshold') fireEvent.change(screen.getByLabelText('Minimum score'), { target: { value: '12' } });
  else if (change === 'weights') fireEvent.change(screen.getAllByRole('spinbutton', { name: / 가중치$/ })[0], { target: { value: '0.25' } });
  else fireEvent.click(screen.getByRole('button', { name: '대형 서비스 노이즈 줄이기' }));
  fireEvent.submit(form);
  await waitFor(() => expect(put).toHaveBeenCalledTimes(2));
  await screen.findByText('Owned capture interruption');
  expect(post).toHaveBeenCalledTimes(2);
  expect(put.mock.calls[1][0]).toBe('/pcap-analysis-jobs/B/capture');
  const [a, b] = post.mock.calls.map(call => call[1] as Record<string, unknown>);
  expect(b.idempotency_key).not.toBe(a.idempotency_key);
  if (!change.endsWith('file')) expect(b).not.toEqual({ ...a, idempotency_key: b.idempotency_key });
});

it('does not confuse latest B mutation variables with A admission after B initiation fails', async () => {
  const post = vi.spyOn(api, 'post').mockResolvedValueOnce({ id: 'A' }).mockRejectedValueOnce(new Error('B initiation failed')).mockResolvedValueOnce({ id: 'B' });
  const put = vi.spyOn(api, 'uploadWithProgress').mockRejectedValue(new Error('Owned capture interruption'));
  const { form } = await uploadForm();
  fireEvent.submit(form);
  await screen.findByText('Owned capture interruption');
  fireEvent.change(screen.getByLabelText('Minimum packets'), { target: { value: '55' } });
  fireEvent.submit(form);
  await screen.findByText('B initiation failed');
  expect(put).toHaveBeenCalledTimes(1);
  expect(screen.queryByRole('button', { name: '기존 작업으로 업로드 재시도' })).not.toBeInTheDocument();
  fireEvent.submit(form);
  await waitFor(() => expect(put).toHaveBeenCalledTimes(2));
  await screen.findByText('Owned capture interruption');
  expect(post).toHaveBeenCalledTimes(3);
  expect(post.mock.calls[2][1]).toBe(post.mock.calls[1][1]);
  expect(put.mock.calls[1][0]).toBe('/pcap-analysis-jobs/B/capture');
});

function clickCallback(button: HTMLElement): () => void {
  const key = Object.keys(button).find(key => key.startsWith('__reactProps$'))!;
  return (button as unknown as Record<string, { onClick: () => void }>)[key].onClick;
}

it.each(['module', 'file', 'form', 'weights', 'unmount'])('captured explicit retry cannot dispatch after %s retirement', async change => {
  const post = vi.spyOn(api, 'post').mockResolvedValue({ id: 'A' });
  const put = vi.spyOn(api, 'uploadWithProgress').mockRejectedValue(new Error('Owned capture interruption'));
  const { form, unmount } = await uploadForm('c2');
  fireEvent.submit(form);
  await screen.findByText('Owned capture interruption');
  const captured = clickCallback(screen.getByRole('button', { name: '기존 작업으로 업로드 재시도' }));
  if (change === 'module') {
    fireEvent.change(screen.getByLabelText('Analysis module'), { target: { value: 'network_anomaly' } });
    fireEvent.change(screen.getByLabelText('Analysis module'), { target: { value: 'c2' } });
  } else if (change === 'file') fireEvent.change(screen.getByLabelText('Capture file'), { target: { files: [new File(['pcap'], 'owned.pcap')] } });
  else if (change === 'form') fireEvent.change(screen.getByLabelText('Analysis name'), { target: { value: 'Changed' } });
  else if (change === 'weights') fireEvent.click(screen.getByRole('button', { name: '대형 서비스 노이즈 줄이기' }));
  else unmount();
  await act(async () => { captured(); });
  expect(post).toHaveBeenCalledTimes(1);
  expect(put).toHaveBeenCalledTimes(1);
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

it.each([['initiation', 'success'], ['initiation', 'failure'], ['upload', 'success'], ['upload', 'failure']])('pending %s %s A -> B -> A cannot resurrect, publish or settle a new invocation', async (phase, outcome) => {
  const first = deferred<{ id: string }>();
  const latest = deferred<{ id: string }>();
  const post = vi.spyOn(api, 'post');
  const put = vi.spyOn(api, 'uploadWithProgress');
  if (phase === 'initiation') {
    post.mockRejectedValue(new Error('Current capture interruption')).mockImplementationOnce(() => first.promise).mockImplementationOnce(() => latest.promise);
    put.mockRejectedValue(new Error('Current capture interruption'));
  } else {
    post.mockResolvedValueOnce({ id: 'A' }).mockResolvedValueOnce({ id: 'B' });
    put.mockRejectedValue(new Error('Current capture interruption')).mockImplementationOnce(() => first.promise).mockImplementationOnce(() => latest.promise);
  }
  const { form } = await uploadForm('c2');
  fireEvent.submit(form);
  await waitFor(() => expect(phase === 'initiation' ? post : put).toHaveBeenCalledTimes(1));
  fireEvent.change(screen.getByLabelText('Analysis module'), { target: { value: 'network_anomaly' } });
  fireEvent.change(screen.getByLabelText('Analysis module'), { target: { value: 'c2' } });
  // The real file-input path resets the mutation observer while old IO remains.
  fireEvent.change(screen.getByLabelText('Capture file'), { target: { files: [new File(['PCAP'], 'owned.pcap')] } });
  fireEvent.submit(form);
  await waitFor(() => expect(phase === 'initiation' ? post : put).toHaveBeenCalledTimes(2));
  if (phase === 'upload') {
    await act(async () => { put.mock.calls[1][3]!({ loaded: 1, total: 4 }); });
    await act(async () => { put.mock.calls[0][3]!({ loaded: 4, total: 4 }); });
    expect(screen.getByRole('progressbar', { name: 'PCAP upload progress' })).toHaveAttribute('value', '1');
  }
  await act(async () => { if (outcome === 'success') first.resolve({ id: 'A' }); else first.reject(new Error('Retired failure')); });
  expect(screen.getByRole('heading', { name: 'Upload PCAP' })).toBeVisible();
  expect(screen.getByRole('button', { name: 'Uploading and analyzing…' })).toBeDisabled();
  fireEvent.submit(form);
  await act(async () => {});
  expect(post).toHaveBeenCalledTimes(2);
  expect(put).toHaveBeenCalledTimes(phase === 'initiation' ? 0 : 2);
  await act(async () => { latest.reject(new Error('Current failure')); });
  await screen.findByText('Current failure');
  fireEvent.submit(form);
  if (phase === 'initiation') {
    await waitFor(() => expect(post).toHaveBeenCalledTimes(3));
    expect(post.mock.calls[2][1]).toBe(post.mock.calls[1][1]);
  } else await waitFor(() => expect(put).toHaveBeenCalledTimes(3));
  await screen.findByText('Current capture interruption');
});

it('a preset-mode change retires pending wire intent even when its select has no form name', async () => {
  const pending = deferred<{ id: string }>();
  const post = vi.spyOn(api, 'post').mockResolvedValue({ id: 'A' });
  const put = vi.spyOn(api, 'uploadWithProgress').mockRejectedValue(new Error('Current capture interruption')).mockImplementationOnce(() => pending.promise);
  const { form } = await uploadForm('c2', true);
  await waitFor(() => expect(screen.getByLabelText('저장된 탐지 가중치 프리셋')).toHaveValue('default'));
  fireEvent.submit(form);
  await waitFor(() => expect(put).toHaveBeenCalledTimes(1));
  expect(post.mock.calls[0][1]).not.toHaveProperty('analysis.detector_weights');
  fireEvent.change(screen.getByLabelText('저장된 탐지 가중치 프리셋'), { target: { value: '' } });
  await act(async () => { pending.resolve({ id: 'A' }); });
  expect(screen.getByRole('heading', { name: 'Upload PCAP' })).toBeVisible();
  fireEvent.submit(form);
  await waitFor(() => expect(post).toHaveBeenCalledTimes(2));
  expect(post.mock.calls[1][1]).toHaveProperty('analysis.detector_weights');
  await screen.findByText('Current capture interruption');
});

it('compares the actual wire body at submit, independently of change-event invalidation', async () => {
  const post = vi.spyOn(api, 'post').mockResolvedValueOnce({ id: 'A' }).mockResolvedValueOnce({ id: 'B' });
  const put = vi.spyOn(api, 'uploadWithProgress').mockRejectedValue(new Error('Owned capture interruption'));
  const { form } = await uploadForm('c2');
  fireEvent.submit(form);
  await screen.findByText('Owned capture interruption');
  // FormData sees this value even without a bubbled React change event.
  (screen.getByLabelText('Internal networks') as HTMLInputElement).value = '192.0.2.0/24';
  fireEvent.submit(form);
  await waitFor(() => expect(put).toHaveBeenCalledTimes(2));
  await screen.findByText('Owned capture interruption');
  expect(post).toHaveBeenCalledTimes(2);
  expect(post.mock.calls[1][1]).toHaveProperty('internal_networks', ['192.0.2.0/24']);
  expect(put.mock.calls[1][0]).toBe('/pcap-analysis-jobs/B/capture');
});
