import { expect, it } from 'vitest';
import { parseJobWire } from '../src/jobInvestigationContract';
import { producer, pythonAcceptance } from './jobInvestigationFixtures';

it('BLOCKING parity: an interpretation cannot cite a metric absent from its saved facts',()=>{
  const original=producer.fixtures.run_completed;
  const run=parseJobWire('run',original);
  if(run.result?.kind!=='RESULT')throw Error('fixture result missing');
  const a=run.result.assessments[0];expect(a.facts).toHaveLength(0);
  const id=a.support[0].evidence_ids[0];
  const raw=original.replace('"metric_refs":[]',`"metric_refs":["${id}:matched_rows"]`);
  expect(raw).not.toBe(original);
  const python=pythonAcceptance([{kind:'run',raw}])[0];
  let web=false;try{parseJobWire('run',raw);web=true;}catch{/*closed refusal*/}
  console.log(JSON.stringify({case:'missing-saved-fact',expected:false,raw,python,web}));
  expect(web).toBe(false);expect(python.accepted).toBe(false);
});
