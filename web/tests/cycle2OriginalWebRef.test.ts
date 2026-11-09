import { expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import wire from './cycle2OriginalWebRef.json';
import { pythonAcceptance } from './jobInvestigationFixtures';
import { parseJobWire } from '../src/jobInvestigationContract';
const python=pythonAcceptance([wire]);
it('original immutable WEB-REF bytes reject in both consumers',()=>{
 expect(createHash('sha256').update(wire.raw).digest('hex')).toBe(wire.sha256);
 expect(python[0].accepted).toBe(false);expect(()=>parseJobWire('run',wire.raw)).toThrow();
});
