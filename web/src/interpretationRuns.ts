import { api } from './api';
import { captureAuthentication, currentAuthentication } from './authentication';

export type InterpretationRuns<T> = { items: T[]; current_page?: number; page_size?: number; total?: number; paginationValid?: boolean; latestModule?: T; discovery?: 'unknown' | 'incomplete' | 'resolved'; nextPage?: number };
const statuses = new Set(['QUEUED', 'PREPARING', 'ANALYZING', 'VALIDATING', 'COMPLETED', 'FAILED', 'CANCELLED']);
export function validInterpretationRecord(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;
  const row = value as Record<string, unknown>;
  return ['id', 'analysis_kind'].every(key => typeof row[key] === 'string' && row[key].length > 0 && row[key].length <= 200)
    && typeof row.status === 'string' && statuses.has(row.status) && (row.language === 'en' || row.language === 'ko');
}
export function matchingInterpretationRecord<T>(value: T, expected: { id: string; analysis_kind: string; dataset_id?: string }, jobId: string): T | undefined {
  if (!validInterpretationRecord(value)) return undefined;
  const row = value as Record<string, unknown>;
  if (row.id !== expected.id || row.analysis_kind !== expected.analysis_kind) return undefined;
  if (Object.hasOwn(row, 'analysis_job_id') && row.analysis_job_id !== jobId) return undefined;
  if (Object.hasOwn(row, 'dataset_id') && (typeof row.dataset_id !== 'string' || !row.dataset_id || expected.dataset_id !== undefined && row.dataset_id !== expected.dataset_id)) return undefined;
  return value;
}
export function interpretationPage<T>(value: InterpretationRuns<T>, page: number): InterpretationRuns<T> {
  const raw = Array.isArray(value?.items) ? value.items : [];
  // Read-only identity is not proof of module ownership or requested language.
  const items = raw.slice(0, 200).filter(value => {
    if (!value || typeof value !== 'object') return false;
    const row = value as Record<string, unknown>;
    return typeof row.id === 'string' && row.id.length > 0 && row.id.length <= 200 && typeof row.status === 'string' && statuses.has(row.status);
  });
  const size = value?.page_size, total = value?.total;
  const paginationValid = Array.isArray(value?.items) && raw.length <= 200
    && value.current_page === page && Number.isSafeInteger(size) && size! >= 1 && size! <= 200
    && Number.isSafeInteger(total) && total! >= 0 && Number.isSafeInteger((page - 1) * size!)
    && raw.length === Math.max(0, Math.min(size!, total! - (page - 1) * size!));
  const valid = paginationValid && raw.every(validInterpretationRecord);
  return { items, current_page: value?.current_page, page_size: size, total, paginationValid, discovery: valid ? 'incomplete' : 'unknown' };
}
// One automatic page. Manual history is published independently of discovery.
export async function readInterpretationRuns<T extends { analysis_kind: string }>(jobId: string, kind: string, signal: AbortSignal): Promise<InterpretationRuns<T>> {
  const authentication = captureAuthentication();
  const live = () => { if (signal.aborted || !currentAuthentication(authentication)) throw new Error('Saved run lookup retired'); };
  live();
  const raw = await api.get<InterpretationRuns<T>>(`/analysis-jobs/${encodeURIComponent(jobId)}/ai-runs`);
  live();
  const first = interpretationPage(raw, 1);
  if (first.discovery === 'unknown') return first;
  const latestModule = first.items.find(item => item.analysis_kind === kind);
  return { ...first, latestModule, discovery: latestModule || first.items.length === first.total ? 'resolved' : 'incomplete', nextPage: 2 };
}
