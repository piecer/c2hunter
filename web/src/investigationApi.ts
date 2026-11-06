import { api } from './api';
import { assertIdentity, InvestigationContractError, parseInvestigation, parsePage, sameExecution, sameScope } from './investigationContract';
import type { InvestigationRequest, InvestigationRun, Scope } from './investigationTypes';

const base = (job: string) => `/analysis-jobs/${encodeURIComponent(job)}/ai-investigations`;
const path = (job: string, id: string) => `${base(job)}/${encodeURIComponent(id)}`;
export const investigationApi = {
  async capabilities(signal: AbortSignal) {
    let unavailableReason: string | null = null;
    const document = parseInvestigation('InvestigationCapabilities', await api.boundedRequest('/ai-investigations/capabilities', { signal }, headers => {
      const value = headers.get('x-investigation-unavailable-reason');
      const allowed = ['STORE_NOT_INITIALIZED', 'UNSUPPORTED_REPOSITORY', 'STORAGE_UNAVAILABLE', 'PROVIDER_UNSUPPORTED', 'DISPATCH_UNAVAILABLE'];
      unavailableReason = value === null ? null : allowed.includes(value) ? value : 'UNRECOGNIZED_UNAVAILABLE_REASON';
    }));
    return { document, unavailableReason };
  },
  async preview(job: string, scope: Scope, signal: AbortSignal) {
    const value = parseInvestigation('SourcePreview', await api.boundedRequest(`${base(job)}/source-preview`, { method: 'POST', body: JSON.stringify(scope), signal }));
    if (value.source.job_id !== job || !sameScope(value.scope, scope)) throw new InvestigationContractError();
    return value;
  },
  async create(job: string, captured: string, signal: AbortSignal) {
    const request = parseInvestigation('InvestigationRequest', JSON.parse(captured));
    if (new TextEncoder().encode(captured).byteLength > 16 * 1024) throw new InvestigationContractError();
    const run = parseInvestigation('InvestigationRun', await api.boundedRequest(base(job), { method: 'POST', body: captured, signal }));
    assertIdentity(run, job, { request });
    return run;
  },
  async history(job: string, after: string | null, signal: AbortSignal) {
    const page = parsePage('InvestigationRun', await api.boundedRequest(`${base(job)}?limit=5${after ? `&after=${encodeURIComponent(after)}` : ''}`, { signal }));
    page.items.forEach(run => assertIdentity(run, job));
    if (page.next_cursor !== null && page.next_cursor === after) throw new InvestigationContractError();
    return page;
  },
  async run(job: string, expected: InvestigationRun, signal: AbortSignal) {
    const run = parseInvestigation('InvestigationRun', await api.boundedRequest(path(job, expected.id), { signal }));
    assertIdentity(run, job, { id: expected.id, request: expected.request, scope: expected.scope });
    if (run.owner_id !== expected.owner_id || run.revision < expected.revision || !sameExecution(run.execution, expected.execution)) throw new InvestigationContractError();
    return run;
  },
  async cancel(job: string, expected: InvestigationRun, signal: AbortSignal) {
    const run = parseInvestigation('InvestigationRun', await api.boundedRequest(`${path(job, expected.id)}/cancel`, { method: 'POST', signal }));
    assertIdentity(run, job, { id: expected.id, request: expected.request, scope: expected.scope });
    if (run.owner_id !== expected.owner_id || run.revision < expected.revision || !sameExecution(run.execution, expected.execution)) throw new InvestigationContractError();
    return run;
  },
  async steps(job: string, run: InvestigationRun, after: number, signal: AbortSignal) {
    const page = parsePage('InvestigationStep', await api.boundedRequest(`${path(job, run.id)}/steps?after=${after}&limit=10`, { signal }));
    if (page.items.some(step => step.sequence <= after)) throw new InvestigationContractError();
    return page;
  },
  async evidence(job: string, run: InvestigationRun, id: string, signal: AbortSignal) {
    const evidence = parseInvestigation('Evidence', await api.boundedRequest(`${path(job, run.id)}/evidence/${encodeURIComponent(id)}`, { signal }));
    if (evidence.evidence_id !== id || evidence.source.job_id !== job || evidence.source.source_sha256 !== run.request.expected_source_sha256 || !sameScope(evidence.scope, run.scope)) throw new InvestigationContractError();
    return evidence;
  },
};
export function captureRequest(scope: Scope, question: string, language: 'ko' | 'en', source: string, allowRemote: boolean): string {
  const key = crypto.randomUUID?.() ?? [...crypto.getRandomValues(new Uint8Array(16))].map(byte => byte.toString(16).padStart(2, '0')).join('');
  const request: InvestigationRequest = { ...scope, version: 'ip-investigation-v1', mode: 'IP', question, language, expected_source_sha256: source, idempotency_key: key, allow_remote: allowRemote };
  parseInvestigation('InvestigationRequest', request);
  return JSON.stringify(request);
}
