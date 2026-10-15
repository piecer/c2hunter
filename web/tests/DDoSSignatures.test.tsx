import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { readFileSync } from 'node:fs';
import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import DDoSAttackPanel from '../src/DDoSAttackPanel';

const corpusBytes = readFileSync('tests/fixtures/ddos-signature-corpus.json', 'utf8');
const corpus = JSON.parse(corpusBytes);
it('freezes exact producer corpus bytes', () => {
  expect(execFileSync(resolve('../.venv/bin/python'), ['tests/ddos_signature_corpus.py'], { encoding: 'utf8' })).toBe(corpusBytes);
});
for (const c of corpus) {
  it(`shared signature corpus: ${c.name}`, () => {
    render(<DDoSAttackPanel report={c.report}/>);
    expect(Boolean(screen.queryByRole('alert'))).toBe(!c.accepted);
  });
}

it('accepts actual v4 producer bytes and rejects invented measurements', () => {
  const report = JSON.parse(execFileSync(resolve('../.venv/bin/python'), ['tests/ddos_report_fixture.py'], { encoding: 'utf8' }));
  expect(report.version).toBe('ddos-attack-report-v4');
  const { unmount } = render(<DDoSAttackPanel report={report}/>);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  unmount();
  report.findings[0].signature_candidates[0].evaluation.attack.packet_match_rate = 0;
  render(<DDoSAttackPanel report={report}/>);
  expect(screen.getByRole('alert')).toBeInTheDocument();
});
