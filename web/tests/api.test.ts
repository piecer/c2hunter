import { describe, expect, it, vi } from 'vitest';
import { api } from '../src/api';

describe('api client', () => {
  it('adds authentication and decodes API error envelopes', async () => {
    localStorage.setItem('c2hunter-token', 'dev-token');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { code: 'DENIED', message: 'No access' } }), { status: 403, headers: { 'content-type': 'application/json' } })));
    await expect(api.get('/sensors')).rejects.toMatchObject({ code: 'DENIED', message: 'No access', status: 403 });
    expect(fetch).toHaveBeenCalledWith('/api/v1/sensors', expect.objectContaining({ headers: expect.objectContaining({ authorization: 'Bearer dev-token' }) }));
  });

  it('preserves binary upload content type instead of forcing JSON', async () => {
    localStorage.setItem('c2hunter-token', 'dev-token');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ id: 'job-1' }), { status: 201, headers: { 'content-type': 'application/json' } })));
    const capture = new Blob([new Uint8Array([1, 2, 3])]);

    await api.upload('/pcap-analysis-jobs?name=test', capture, 'application/vnd.tcpdump.pcap');

    expect(fetch).toHaveBeenCalledWith('/api/v1/pcap-analysis-jobs?name=test', expect.objectContaining({ body: capture, headers: expect.objectContaining({ authorization: 'Bearer dev-token', 'content-type': 'application/vnd.tcpdump.pcap' }) }));
  });
});
