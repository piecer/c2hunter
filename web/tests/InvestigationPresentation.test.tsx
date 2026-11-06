import { fireEvent, render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import { InvestigationEvidence } from '../src/InvestigationResult';
import { parseInvestigation } from '../src/investigationContract';
import { fixture } from './investigationFixtures';

it.each(['peer_overview', 'peer_flow_samples', 'peer_timeline', 'peer_protocol_observations', 'compare_peer_cohort'])('keeps every actual %s metric reachable with bounded mounted cards', tool => {
  const evidence = parseInvestigation('Evidence', fixture(tool));
  const view = render(<div className="investigation-panel"><InvestigationEvidence evidence={evidence}/></div>);
  const reached = new Set<string>();
  for (let page = 0; page <= Math.ceil(evidence.metrics.length / 4); page += 1) {
    for (const metric of evidence.metrics) if (screen.queryByText(metric.ref, { exact: true })) reached.add(metric.ref);
    expect(view.container.querySelectorAll('.investigation-fact').length).toBeLessThanOrEqual(4);
    expect(view.container.querySelectorAll('*').length).toBeLessThan(900);
    const next = screen.queryByRole('button', { name: '다음 / Next facts' });
    if (!next || next.hasAttribute('disabled')) break;
    fireEvent.click(next);
  }
  expect([...reached].sort()).toEqual(evidence.metrics.map(metric => metric.ref).sort());
  if (tool === 'peer_flow_samples') {
    expect(screen.getAllByText(/present_fields preserves source field absence/).length).toBeGreaterThan(0);
    expect(screen.getAllByText('complete_transport_packet', { exact: true }).length).toBeGreaterThan(0);
  }
});
