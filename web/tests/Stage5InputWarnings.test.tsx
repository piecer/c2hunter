import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';
import { api } from '../src/api';

for (const route of ['/analyses/new', '/analyses/upload']) {
  for (const module of ['ddos_attack', 'network_anomaly']) {
    it(`${route} ${module} keeps interpretation limits visible without opening advanced settings`, async () => {
      localStorage.setItem('c2hunter-token', 'warning-probe');
      localStorage.setItem('c2hunter-report-language', 'en');
      vi.spyOn(api, 'get').mockImplementation(async path => {
        if (path === '/sensors') return { items: [{ sensor_id: 'sensor-A', name: 'Sensor A' }] };
        if (path === '/detector-weight-presets') return { items: [] };
        throw new Error(`Unexpected read ${path}`);
      });
      const post = vi.spyOn(api, 'post');
      const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
      const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[route]}><App/></MemoryRouter></QueryClientProvider>);
      try {
        fireEvent.change(await screen.findByLabelText('Analysis module'), { target: { value: module } });
        const limit = module === 'ddos_attack'
          ? /Source addresses are observations, not confirmed attackers/
          : /A single vantage point cannot prove path loss or its location/;
        const region = screen.getByRole('region', { name: 'Interpretation limits' });
        expect(within(region).getByText(limit)).toBeVisible();
        expect(screen.getByText('Advanced options / 고급 설정').closest('details')).not.toHaveAttribute('open');
        for (const semantic of module === 'ddos_attack'
          ? [/missing baseline.*possible/i, /not attribute actors/, /prove service impact/, /application-layer/, /execute mitigations/]
          // Interpretation/capture checklist from the retained NetworkObservationHelp,
          // not an oracle derived from the new compact summary.
          : [/Missing evidence.*not.*zero anomalies/, /packet-level PCAP/i, /timestamps/, /both directions/, /Aggregated.*missing packet-level/, /ICMP echo RTT is not supplied by the current modern producer/, /TCP RTT requires eligible sequence\/ACK matches and timestamps/, /capture directions and BPF filters broad enough to include replies/]) {
          expect.soft(region).toHaveTextContent(semantic);
          if (module === 'network_anomaly') {
            expect(screen.getByText('Network observations and capture evidence').closest('section')).toHaveTextContent(semantic);
          }
        }
        expect(post).not.toHaveBeenCalled();
      } finally {
        view.unmount();
        client.clear();
      }
    });
  }
}
