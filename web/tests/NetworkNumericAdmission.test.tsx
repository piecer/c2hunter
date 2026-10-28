import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import NetworkAI from '../src/NetworkAIInterpretation';
import { NetworkEvidenceContext } from '../src/networkEvidenceContext';
import { ReportLanguageContext } from '../src/reportLanguageContext';
import { projectNetworkReport } from '../src/networkReportValidation';
import { parseNumericRun } from '../src/networkNumericEvidence';

const python = process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python');
const fixture = JSON.parse(execFileSync(python, ['tests/network_numeric_fixture.py'], { encoding: 'utf8', maxBuffer: 20000000 }));
// Mutate actual public producer bytes; Python and Web decode the SAME raw string.
// Bookkeeping follows the removed units, so rejection is not a stale-count accident.
const paired: { name: string; raw: string; accepted: boolean; python: boolean }[] = JSON.parse(execFileSync(python, ['-c', `
import json, sys
from copy import deepcopy
from c2hunter_controller.network_numeric_evidence import validate_output, EvidenceIdentity
base = json.load(sys.stdin)['run']
base['network_interpretation']['summary_numeric_refs'] = [{'kind':'summary_count','field':'scanned_records'}]
_, base['network_numeric_evidence'] = validate_output(base['network_interpretation'], base['network_input'], EvidenceIdentity.from_run(base))
cases = []
for key in ['observed_measurements','observed_facts','evidence','uncertainty','next_checks','detailed_analysis']:
    for mode in ['null','absent','empty']:
        r = deepcopy(base)
        issue = r['network_input']['issues'][0]
        n = len(issue.get(key, []))
        if mode == 'absent': issue.pop(key, None)
        else: issue[key] = None if mode == 'null' else []
        d = r['network_input']['input_detail_counts']
        d['retained'] -= n
        d['omitted'] += n
        raw = json.dumps(r, ensure_ascii=True, separators=(',',':'))
        decoded = json.loads(raw)
        try:
            validate_output(decoded['network_interpretation'], decoded['network_input'], EvidenceIdentity.from_run(decoded))
            actual = True
        except (ValueError, TypeError, KeyError): actual = False
        expected = mode == 'empty' or mode == 'absent' and key in ['observed_measurements','detailed_analysis']
        assert actual == expected, (key, mode, actual)
        cases.append(dict(name=key+'-'+mode, raw=raw, accepted=expected, python=actual))
print(json.dumps(cases))
`], { input: JSON.stringify(fixture), encoding: 'utf8', maxBuffer: 20000000 }));
const clients: QueryClient[] = [];
afterEach(() => { cleanup(); clients.splice(0).forEach(client => client.clear()); });
function show(run: typeof fixture.run) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity, structuralSharing: false } } });
  clients.push(client);
  client.setQueryData(['ai-capabilities'], { available: true, network_interpretation: true, remote: false });
  client.setQueryData(['ai-runs', 'numeric-job'], { items: [run] });
  client.setQueryData(['ai-run', run.id], run);
  const navigate = vi.fn();
  const context = { job: fixture.job, projection: projectNetworkReport(fixture.report), generation: {}, current: () => true, navigate };
  const view = () => <QueryClientProvider client={client}><ReportLanguageContext value="en"><NetworkEvidenceContext value={context}><NetworkAI jobId="numeric-job" completed/></NetworkEvidenceContext></ReportLanguageContext></QueryClientProvider>;
  const ui = render(view());
  fireEvent.click(screen.getByRole('button', { name: 'Open AI interpretation' }));
  return { client, navigate, rerender: () => ui.rerender(view()) };
}
function refused() {
  expect(screen.queryByRole('region', { name: 'Verified numeric source facts' })).toBeNull();
  expect(screen.queryByText('Legacy AI output — no verified numeric evidence.')).toBeNull();
  expect(screen.queryByRole('button', { name: 'View full AI text' })).toBeNull();
  expect(screen.queryAllByRole('button', { name: /Source:/ })).toHaveLength(0);
}
it.each(['missing', 'unknown', 'explicit-v1'])('F2 stored v2 with v1 output and %s top binding refuses legacy fallback', fault => {
  const run = structuredClone(fixture.run);
  if (fault === 'missing') delete run.input_schema_version;
  else run.input_schema_version = fault === 'unknown' ? 'future' : 'network-ai-input-v1';
  run.network_interpretation.schema_version = 'network-interpretation-v1';
  expect(parseNumericRun(run)).toBeUndefined();
  show(run);
  refused();
});
function legacy(provenance = true) {
  const run = structuredClone(fixture.run);
  delete run.network_numeric_evidence;
  run.network_interpretation.schema_version = 'network-interpretation-v1';
  delete run.network_interpretation.summary_numeric_refs;
  if (provenance) {
    run.input_schema_version = 'network-ai-input-v1';
    run.network_input.schema_version = 'network-ai-input-v1';
  } else {
    delete run.input_schema_version;
    delete run.network_input;
  }
  return run;
}
it('F2 legacy provenance does not require a new top-level language field', () => {
  const run = legacy();
  delete run.language;
  show(run);
  expect(screen.getByText('Legacy AI output — no verified numeric evidence.')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'View full AI text' }));
  expect(screen.getByRole('article', { name: 'Full AI interpretation' })).toHaveTextContent('AI says 1100 ms');
});
it.each([false, true])('F2 recognized v1 remains visible and unverified; provenance=%s', provenance => {
  show(legacy(provenance));
  expect(screen.getByText('Legacy AI output — no verified numeric evidence.')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'View full AI text' }));
  expect(screen.getByRole('article', { name: 'Full AI interpretation' })).toHaveTextContent('AI says 1100 ms');
  expect(screen.queryByRole('region', { name: 'Verified numeric source facts' })).toBeNull();
});
it.each(['top-unknown', 'input-unknown', 'output-unknown', 'top-null', 'input-null', 'input-schema-absent', 'top-v2', 'input-v2', 'output-v2'])('F2 unknown or contradictory markers fail closed: %s', fault => {
  const run = legacy();
  if (fault === 'top-unknown') run.input_schema_version = 'future';
  if (fault === 'input-unknown') run.network_input.schema_version = 'future';
  if (fault === 'output-unknown') run.network_interpretation.schema_version = 'future';
  if (fault === 'top-null') run.input_schema_version = null;
  if (fault === 'input-null') run.network_input = null;
  if (fault === 'input-schema-absent') delete run.network_input.schema_version;
  if (fault === 'top-v2') run.input_schema_version = 'network-ai-input-v2';
  if (fault === 'input-v2') run.network_input.schema_version = 'network-ai-input-v2';
  if (fault === 'output-v2') run.network_interpretation.schema_version = 'network-interpretation-v2';
  show(run);
  refused();
});
it.each(['v2', 'legacy', 'contradictory'])('F3 actual display rejects hooks across all boundaries: %s', version => {
  // Separate mounts observe every hook's actual component path, including expanded text.
  for (const boundary of ['root', 'input', 'output', 'input-marker', 'output-marker', 'top-marker', 'input-object', 'output-object', 'output-array', 'input-array']) {
    for (const fault of ['getter', 'toJSON', 'prototype', 'hole']) {
      if (fault === 'hole' && !boundary.endsWith('array')) continue;
      if (boundary.includes('marker') || boundary.endsWith('object')) { if (fault !== 'getter') continue; }
      const run = version === 'legacy' ? legacy() : structuredClone(fixture.run);
      if (version === 'contradictory') { delete run.input_schema_version; run.network_interpretation.schema_version = 'network-interpretation-v1'; }
      let calls = 0;
      const trap = () => { calls++; return 'network-interpretation-v1'; };
      const target = boundary === 'root' || boundary === 'top-marker' || boundary.endsWith('object') ? run : boundary.startsWith('input') ? boundary.endsWith('array') ? run.network_input.issues : run.network_input : boundary.endsWith('array') ? run.network_interpretation.limitations : run.network_interpretation;
      if (fault === 'getter') {
        const key = boundary === 'top-marker' ? 'input_schema_version' : boundary === 'input-object' ? 'network_input' : boundary === 'output-object' ? 'network_interpretation' : boundary.includes('marker') ? 'schema_version' : boundary.endsWith('array') ? '0' : 'toJSON';
        Object.defineProperty(target, key, { enumerable: true, get: trap });
      } else if (fault === 'toJSON') target.toJSON = trap;
      else if (fault === 'prototype') Object.setPrototypeOf(target, { toJSON: trap });
      else delete target[0];
      show(run);
      expect.soft(calls, `${version}/${boundary}/${fault}`).toBe(0);
      expect.soft(screen.queryByText('Legacy AI output — no verified numeric evidence.'), `${boundary}/${fault}`).toBeNull();
      expect.soft(screen.queryByRole('region', { name: 'Verified numeric source facts' }), `${boundary}/${fault}`).toBeNull();
      expect.soft(screen.queryByRole('button', { name: 'View full AI text' }), `${boundary}/${fault}`).toBeNull();
      cleanup();
    }
  }
});
it.each(paired)('F1 same-byte Python/Web admission and actual display: $name', c => {
  const run = JSON.parse(c.raw);
  const parsed = parseNumericRun(run);
  const ui = show(run);
  expect.soft(c.python).toBe(c.accepted);
  expect.soft(Boolean(parsed)).toBe(c.accepted);
  expect.soft(Boolean(screen.queryByRole('region', { name: 'Verified numeric source facts' }))).toBe(c.accepted);
  if (!c.accepted) refused();
  expect(ui.navigate).not.toHaveBeenCalled();
});
it('observed shared-object A-B-A render cannot revive verified facts', () => {
  const run = structuredClone(fixture.run);
  const ui = show(run);
  expect(screen.getByRole('region', { name: 'Verified numeric source facts' })).toBeVisible();
  const value = run.network_numeric_evidence.items[0].value;
  run.network_numeric_evidence.items[0].value = '1100.0';
  ui.rerender(); // Same-object setQueryData alone does NOT prove a render.
  expect(screen.queryByRole('region', { name: 'Verified numeric source facts' })).toBeNull();
  run.network_numeric_evidence.items[0].value = value;
  ui.rerender();
  expect(screen.queryByRole('region', { name: 'Verified numeric source facts' })).toBeNull();
});
it('detached source callback is fenced after an observed changed-object render', () => {
  const run = structuredClone(fixture.run);
  const ui = show(run);
  const button = screen.getByRole('button', { name: /Source: pattern/ });
  const key = Object.keys(button).find(k => k.startsWith('__reactProps'))!;
  const callback = (button as unknown as Record<string, { onClick: () => void }>)[key].onClick;
  run.network_numeric_evidence.items[0].value = '1100.0';
  ui.rerender();
  callback();
  expect(ui.navigate).not.toHaveBeenCalled();
});
it.each(['observed_measurements', 'observed_facts', 'evidence', 'uncertainty', 'next_checks', 'detailed_analysis'])('F1 present undefined is not absent: %s', key => {
  const run = JSON.parse(paired.find(c => c.name === key + '-empty')!.raw);
  run.network_input.issues[0][key] = undefined;
  expect(parseNumericRun(run)).toBeUndefined();
  show(run);
  refused();
});
