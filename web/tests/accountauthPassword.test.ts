import { expect, it } from 'vitest';
import * as security from '../src/accountSecurity';
it.each([[11,false],[12,true],[128,true],[129,false]] as const)('password policy counts Unicode characters (%s) rather than UTF-16 code units', (length,valid)=>{
 expect(security.validAccountPassword('🔒'.repeat(length))).toBe(valid);expect(security.validAccountPassword('a'.repeat(length))).toBe(valid);
});
