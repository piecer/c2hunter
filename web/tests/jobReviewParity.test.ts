import { expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import frozen from './jobReviewFrozenCorpus.json';
import semantic from './jobReviewSemanticCorpus.json';
import { parseJobWire } from '../src/jobInvestigationContract';
import type { JobContracts } from '../src/jobInvestigationTypes';
import { pythonAcceptance } from './jobInvestigationFixtures';

// Preserve each original string and expectation; overrides require a separately
// documented frozen-contract derivation, never the new parser's actual outcome.
const cases = [...frozen, ...semantic];
const answers = pythonAcceptance(cases);
const observations: object[] = [];
it.each(cases.map((c, index) => ({...c,index})))('review exact bytes: $name', c => {
  let web = false;
  try { parseJobWire(c.kind as keyof JobContracts, c.raw); web = true; } catch { /* refuse */ }
  observations.push({name:c.name, sha256:createHash('sha256').update(c.raw).digest('hex'), original_expected:c.accepted, expected:c.accepted, python:answers[c.index].accepted, web});
  expect(answers[c.index].accepted).toBe(c.accepted);
  expect(web).toBe(c.accepted);
});
it('preserves original wire corpus census', () => {
  expect(frozen).toHaveLength(1406);
  expect(observations).toHaveLength(cases.length);
  if(process.env.C2HUNTER_JOB_CORPUS_OUTPUT) writeFileSync(process.env.C2HUNTER_JOB_CORPUS_OUTPUT+'.review', JSON.stringify({cases,observations}));
});
