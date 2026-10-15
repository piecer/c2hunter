import React from 'react';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { render, screen, cleanup } from '@testing-library/react';
import { expect, it } from 'vitest';
import DDoSAttackPanel from '../src/DDoSAttackPanel';
import { validEvaluation } from '../src/ddosSignatures';
const cases = JSON.parse(readFileSync('tests/fixtures/ddos-review-corpus.json', 'utf8'));
it('freezes exact real-producer review corpus', () => {
  expect(execFileSync(process.env.C2HUNTER_TEST_PYTHON || resolve('../.venv/bin/python'), ['tests/ddos_review_corpus.py'], { encoding: 'utf8' }))
    .toBe(readFileSync('tests/fixtures/ddos-review-corpus.json', 'utf8'));
});
for (const c of cases) {
  it(c.name, () => {
    const evaluation = c.report.findings[0]?.signature_candidates[0]?.evaluation;
    if (c.expected && evaluation) expect(validEvaluation(evaluation)).toBe(true);
    if (['duplicate-reference-index-leading-zero', 'noncanonical-distinct-index', 'all-records-some-packets', 'some-records-all-packets'].includes(c.name)) {
      expect(validEvaluation(evaluation)).toBe(false);
    }
    render(<DDoSAttackPanel report={c.report} />);
    const accepted = !screen.queryByRole('alert');
    cleanup();
    expect(accepted).toBe(c.expected);
  });
}
