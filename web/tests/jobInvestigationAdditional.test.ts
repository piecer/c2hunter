import { expect, it } from 'vitest';
import { parseJobWire, poolCommitment } from '../src/jobInvestigationContract';
import { producer, pythonAcceptance } from './jobInvestigationFixtures';
it('fresh actual service creates max-pool, IPv6, three-peer and facts-only witnesses',()=>{
  expect(producer.additional).toBeDefined();
  for(const mode of ['bad_action','final_cap','missing_measurement','cohort_unavailable']) {
    const run=parseJobWire('run',producer.additional['run_review_'+mode]);
    expect(run.status).toBe(mode==='cohort_unavailable'?'COMPLETED':'PARTIAL');
    if(mode==='final_cap')expect(run.result?.reason).toBe('FINAL_LIMIT');
  }
  for(const [name,raw] of Object.entries(producer.additional))parseJobWire(name.startsWith('run_')?'run':name.startsWith('pool_')?'pool':'evidence',raw);
  const complete=parseJobWire('run',producer.additional.run_max_completed);
  expect(complete.pool.entries).toHaveLength(32);expect(complete.pool.omitted_peers).toBeGreaterThan(0);
  expect(complete.coverage.investigated_peers).toBe(3);
  const partial=parseJobWire('run',producer.additional.run_three_facts);
  expect(partial.coverage.investigated_peers).toBe(0);expect(partial.coverage.not_investigated_peers).toBe(3);
  expect(partial.result?.kind==='RESULT'&&partial.result.assessments.every(a=>a.mode==='FACTS_ONLY')).toBe(true);
  const cases=Object.entries(producer.additional).filter(([name])=>name.startsWith('pool_float_')).map(([,raw])=>({kind:'pool',raw}));
  expect(cases).toHaveLength(5);
  for(const {raw} of cases){const pool=parseJobWire('pool',raw);expect(poolCommitment(pool)).toBe(pool.pool_sha256);}
  expect(pythonAcceptance(cases).every(x=>x.accepted)).toBe(true);
});
