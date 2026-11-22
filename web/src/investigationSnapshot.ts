import { assertIdentity, InvestigationContractError, parseInvestigation, sameExecution } from './investigationContract';
import type { InvestigationRun } from './investigationTypes';
import { terminal } from './investigationTypes';

// Runs contain nested records and arrays; request's shallow equality is insufficient.
function sameSnapshot(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object' || Array.isArray(a) !== Array.isArray(b)) return false;
  const left = a as Record<string, unknown>, right = b as Record<string, unknown>;
  return Object.keys(left).length === Object.keys(right).length && Object.keys(left).every(key => Object.hasOwn(right, key) && sameSnapshot(left[key], right[key]));
}

/** History is a fresh observation, not permission to replace an existing owner. */
export function validatedIPSnapshot(value: InvestigationRun, previous: InvestigationRun): InvestigationRun {
  const next = parseInvestigation('InvestigationRun', value);
  assertIdentity(next, previous.job_id, { id: previous.id, request: previous.request, scope: previous.scope });
  if (next.owner_id !== previous.owner_id || next.created_at !== previous.created_at || !sameExecution(next.execution, previous.execution) ||
      next.revision < previous.revision || (next.revision === previous.revision || terminal(previous.status)) && !sameSnapshot(next, previous) ||
      Object.keys(previous.progress).some(key => next.progress[key as keyof typeof next.progress] < previous.progress[key as keyof typeof previous.progress])) {
    throw new InvestigationContractError();
  }
  return next;
}
