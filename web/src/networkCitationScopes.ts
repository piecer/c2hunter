import type { QueryClient } from '@tanstack/react-query';
import { sha256 } from './ddosReportContract';

type Scope = { source: string; numeric?: string; invalid: boolean };
type Registry = { epoch: number; sources: Map<string, string>; runs: Map<string, Scope> };
const registries = new WeakMap<QueryClient, Registry>();
// Bounded descriptors only: no evidence objects, DOM nodes, or authority closures.
// Do not evict and then treat a previously seen identity as a fresh scope. Once
// saturated, unknown identities remain read-only for this client/auth epoch.
export function networkCitationScope(client: QueryClient, epoch: number, jobId: string, runId: string | undefined, signature: string, numericKey: string | undefined): boolean {
  let registry = registries.get(client);
  if (!registry || registry.epoch !== epoch) {
    registry = { epoch, sources: new Map(), runs: new Map() };
    registries.set(client, registry);
  }
  const source = sha256(signature);
  const previous = registry.sources.get(jobId);
  if (previous === undefined && registry.sources.size >= 32) return false;
  if (previous !== source) {
    registry.sources.set(jobId, source);
    for (const [key, value] of registry.runs) if (key.startsWith(`${JSON.stringify(jobId)}:`)) value.invalid = true;
  }
  if (!runId) return false;
  const key = `${JSON.stringify(jobId)}:${JSON.stringify(runId)}`;
  let scope = registry.runs.get(key);
  const numeric = numericKey === undefined ? undefined : sha256(numericKey);
  if (!scope) {
    if (registry.runs.size >= 128) return false;
    scope = { source, numeric, invalid: false };
    registry.runs.set(key, scope);
  } else {
    if (scope.source !== source || scope.numeric !== undefined && scope.numeric !== numeric) scope.invalid = true;
    if (scope.numeric === undefined && numeric !== undefined) scope.numeric = numeric;
  }
  return !scope.invalid;
}
