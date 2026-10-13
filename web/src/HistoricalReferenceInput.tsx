import { useEffect, useRef, useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { api } from './api';
import { historicalAccessDenied, historicalConflict, historicalErrorText } from './historicalReferenceErrors';
import { useReportLanguage } from './reportLanguageContext';

export type BaselineReference = {
  scope_id: string; expected_revision: number; generation_id: string | null;
  target_source_binding_sha256: string; quality_review: null;
};
type Scope = {
  config: { scope_id: string; name: string; kind: 'OPERATIONAL' | 'EVALUATION' };
  control_revision: number; state: string; active: { generation_id: string } | null;
};
type Preview = {
  scope_id: string; scope_revision: number; source_job_id: string; source_binding_sha256: string;
  flow_count: number; profile_count: number; eligible_profile_count: number; excluded_profile_count: number;
  admissible: boolean; reasons: string[];
};

export default function HistoricalReferenceInput({ jobId, value, onChange, disabled, requestError }: {
  jobId: string; value: BaselineReference | null; onChange: (value: BaselineReference | null) => void; disabled: boolean; requestError?: Error | null;
}) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => language === 'ko' ? ko : en;
  const [scopeId, setScopeId] = useState('');
  const owner = useRef(0);
  useEffect(() => () => { owner.current += 1; }, [jobId]);
  const scopes = useQuery<{ items: Scope[] }, Error>({
    queryKey: ['historical-scopes', jobId], queryFn: () => api.get('/historical-baselines/scopes'),
    retry: false, staleTime: Infinity, refetchOnWindowFocus: false, refetchOnReconnect: false,
  });
  const selected = scopes.data?.items.find(scope => scope.config.scope_id === scopeId);
  const preview = useMutation({
    retry: false,
    mutationFn: async ({ scope, token }: { scope: Scope; token: number }) => {
      const result = await api.post<Preview>(`/historical-baselines/scopes/${scope.config.scope_id}/preview`, {
        source_job_id: jobId, expected_revision: scope.control_revision, purpose: 'COMPARISON',
      });
      if (result.source_job_id !== jobId || result.scope_id !== scope.config.scope_id || result.scope_revision !== scope.control_revision || !Number.isSafeInteger(result.scope_revision) || !/^[0-9a-f]{64}$/.test(result.source_binding_sha256)) {
        throw new Error(t('Invalid preview binding; select the scope and preview again.', '미리보기 연결 정보가 유효하지 않습니다. 범위를 선택하고 다시 미리보기하세요.'));
      }
      return { scope, result, token };
    },
    onSuccess: ({ scope, result, token }) => {
      if (token !== owner.current) return;
      onChange({
        scope_id: scope.config.scope_id, expected_revision: scope.control_revision,
        generation_id: scope.active?.generation_id ?? null, target_source_binding_sha256: result.source_binding_sha256, quality_review: null,
      });
    },
  });
  const denied = [scopes.error, preview.error, requestError].some(historicalAccessDenied);
  const stale = [preview.error, requestError].some(historicalConflict);
  return <section className="c2-discovery" aria-label={t('Historical reference options', '과거 참조 설정')}>
    <p className="warning">{t('Authenticated ANALYST access is required. No target quality review is asserted: comparison is UNREVIEWED and may be unusable. Preview counts are not approval or proof of normal traffic. This does not approve or modify a baseline.', '인증된 ANALYST 권한이 필요합니다. 대상 품질 검토를 주장하지 않습니다. 비교는 UNREVIEWED이며 사용할 수 없을 수 있습니다. 미리보기 건수는 승인이나 정상 트래픽의 증명이 아니며 기준선을 승인·변경하지 않습니다.')}</p>
    <label>{t('Historical scope', '과거 참조 범위')}<select value={scopeId} disabled={disabled || denied || scopes.isFetching} onChange={event => { owner.current += 1; setScopeId(event.target.value); onChange(null); preview.reset(); }}>
      <option value="">{t('Select an exact scope', '정확한 범위를 선택하세요')}</option>
      {scopes.data?.items.map(scope => <option key={scope.config.scope_id} value={scope.config.scope_id}>{scope.config.name} · {scope.config.kind} · {scope.config.scope_id}</option>)}
    </select></label>
    {scopes.isLoading && <p role="status">{t('Loading scopes…', '범위 조회 중…')}</p>}
    {scopes.error && <p role="alert">{historicalErrorText(scopes.error, language)}</p>}
    {selected && <dl><dt>{t('Scope ID', '범위 ID')}</dt><dd className="hash-value">{selected.config.scope_id}</dd><dt>{t('Revision', '리비전')}</dt><dd>{selected.control_revision}</dd><dt>{t('Generation', '세대')}</dt><dd className="hash-value">{selected.active?.generation_id ?? t('None (null)', '없음 (null)')}</dd></dl>}
    <button type="button" className="secondary" disabled={!selected || disabled || denied || stale || scopes.isFetching || preview.isPending} onClick={() => { onChange(null); if (selected) preview.mutate({ scope: selected, token: ++owner.current }); }}>{t('Preview reference', '참조 미리보기')}</button>
    <button type="button" className="secondary" disabled={disabled || denied || scopes.isFetching || preview.isPending} onClick={() => { owner.current += 1; setScopeId(''); onChange(null); preview.reset(); void scopes.refetch(); }}>{t('Reload scopes', '범위 다시 불러오기')}</button>
    {preview.isPending && <p role="status">{t('Reading counts-only preview…', '건수 전용 미리보기 조회 중…')}</p>}
    {preview.error && <p role="alert">{historicalErrorText(preview.error, language)}</p>}
    {value && preview.data && <><p role="status">{t('Reference pinned. The server will reject a changed revision, generation or source.', '참조를 고정했습니다. 리비전·세대·원본이 변경되면 서버에서 거부합니다.')}</p><p>{t('Flows / profiles / eligible / excluded', '흐름 / 프로필 / 조건부 적격 / 제외')}: {preview.data.result.flow_count} / {preview.data.result.profile_count} / {preview.data.result.eligible_profile_count} / {preview.data.result.excluded_profile_count}</p>{preview.data.result.reasons.map(reason => <p className="warning" key={reason}><code>{reason}</code></p>)}</>}
  </section>;
}
