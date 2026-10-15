import { useState } from 'react';
import { downloadDDoSExport, passiveSelection, type ExportJob } from './ddosExport';
import type { DDoSAttackReport, DDoSFinding } from './ddosReportContract';
import type { MatchResult } from './ddosSignatures';
import { useReportLanguage } from './reportLanguageContext';
import { choose, falsePositiveCodes, signatureKinds } from './ddosReportTranslations';

const confidenceLabels: Record<string, [string, string]> = { low: ['Low', '낮음'], medium: ['Medium', '보통'], high: ['High', '높음'], unknown: ['Unknown', '미확인'] };

const filterReasons: Record<string, [string, string]> = {
  INVALID_CONTEXT: ['Capture context is malformed or exceeds its budget.', '캡처 문맥이 잘못되었거나 제한을 초과합니다.'],
  INVALID_PREDICATE: ['Predicate is malformed or has unknown conditions.', '조건이 잘못되었거나 알 수 없는 조건을 포함합니다.'],
  UPLOADED_CAPTURE_IDENTITY_REQUIRED: ['Requires an uploaded capture with SHA-256 identity; LIVE/unknown capture context is unsupported.', 'SHA-256 식별자가 있는 업로드 캡처가 필요합니다. LIVE·미확인 캡처 문맥은 지원하지 않습니다.'],
  OBSERVATION_DEPENDENT_OR_UNSUPPORTED_CONDITIONS: ['Only UDP without flags, length or protocol-field conditions is supported. Observation eligibility cannot be discarded.', 'flags·길이·프로토콜 필드 조건이 없는 UDP만 지원합니다. 관측 적격 조건을 버릴 수 없습니다.'],
  IPV4_UDP_ONLY: ['IPv6 targets are not supported by this exact translator.', '이 정확 변환기는 IPv6 대상을 지원하지 않습니다.'],
  DIRECTION_UNSUPPORTED: ['Direction must be explicit INBOUND or OUTBOUND.', '방향은 명시적인 INBOUND 또는 OUTBOUND여야 합니다.'],
  ETHERNET_OR_RAW_IPV4_CAPTURE_REQUIRED: ['Requires a single Ethernet (1) or raw IP (101) link type.', '단일 Ethernet (1) 또는 raw IP (101) 링크 유형이 필요합니다.'],
  BOUNDED_IPV4_NETWORK_CONTEXT_REQUIRED: ['Requires 1–32 valid IPv4 internal networks; mixed IPv6 context is unsupported.', '유효한 IPv4 내부 네트워크 1–32개가 필요합니다. 혼합 IPv6 문맥은 지원하지 않습니다.'],
  PORT_CONDITION_UNSUPPORTED: ['Port conditions cannot be translated exactly.', '포트 조건을 정확히 변환할 수 없습니다.'],
  FILTER_BYTE_LIMIT: ['Exact filter exceeds the 16 KiB expression budget.', '정확한 필터가 표현식 16 KiB 제한을 초과합니다.'],
  SAME_CAPTURE_DECODED_IPV4_UDP_PREDICATE: ['Direction uses internal-network membership, not the capture-interface inbound keyword.', '방향은 캡처 인터페이스의 inbound 키워드가 아닌 내부 네트워크 소속으로 판정합니다.'],
};

export default function DDoSCandidateInspection({ finding, current, report, job }: { finding: DDoSFinding; current: () => boolean; report: DDoSAttackReport; job?: ExportJob }) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => language === 'ko' ? ko : en;
  const [selected, setSelected] = useState<string>();
  const [exportError, setExportError] = useState(false);
  const counts = (result: MatchResult) => <>
    <p>{t('Matched / eligible records; unknown:', '일치 / 평가 가능 레코드; 미확인:')} {result.matched_records} / {result.eligible_records}; {result.unknown_records}</p>
    <p>{t('Matched / eligible packets; unknown:', '일치 / 평가 가능 패킷; 미확인:')} {result.matched_packets} / {result.eligible_packets}; {result.unknown_packets}</p>
    <p>{t('Sampled records / record limit; omitted:', '표본 레코드 / 레코드 한도; 생략:')} {result.sampled_records} / {result.record_limit}; {result.omitted_records}</p>
    <p>{t('Projection bytes / byte limit:', '투영 바이트 / 바이트 한도:')} {result.sample_bytes} / {result.byte_limit}</p>
    <p>{t('Evidence digest:', '근거 다이제스트:')} <code>{result.evidence_digest}</code></p>
    <p>{t('Matched evidence references (at most 8):', '일치 근거 참조 (최대 8개):')} {result.evidence_refs.join(', ') || '—'}</p>
  </>;
  return <><h5>{t('Signature candidates', '시그니처 후보')}</h5>
    <ul>{finding.signature_candidates?.map(signature => {
      const selection = selected === signature.id && signature.evaluation && job ? passiveSelection(signature.evaluation.predicate, job) : null;
      return <li key={signature.id}>
      <strong>{choose(language, signatureKinds[signature.kind])}</strong> — {signature.protocol}
      <p><code>{signature.id}</code></p>
      <small>{t('Candidate only; review and human approval are required before enforcement.', '후보일 뿐이며 적용 전 검토와 운영자 승인이 필요합니다.')}</small>
      <button type="button" className="secondary" aria-expanded={selected === signature.id} onClick={() => { if (current()) setSelected(selected === signature.id ? undefined : signature.id); }}>{t('Inspect candidate', '후보 검토')} — {signature.id}</button>
      {selected === signature.id && <section role="region" aria-label={t('Candidate inspection', '후보 검토 상세')}>
        <p>{t('Candidate confidence', '후보 신뢰도')}: {t(...confidenceLabels[signature.confidence])} — {t('not classification confidence or a calibrated attack probability', '분류 신뢰도 또는 보정된 공격 확률이 아님')}</p>
        {signature.evaluation ? <>
          <p>{t('Evaluated conditions (AND):', '평가한 조건 (AND):')}</p><pre>{JSON.stringify(signature.evaluation.predicate, null, 2)}</pre>
          <h6>{t('Attack-window retained evidence', '공격 구간 보존 근거')}</h6>{counts(signature.evaluation.attack)}
          <h6>{t('Independent operator-selected normal reference', '독립적으로 운영자가 선택한 정상 참조')}</h6>
          {signature.evaluation.normal.status === 'UNMEASURED' ? <p>{t('Unmeasured, not zero false positives', '미측정 — 오탐 0이 아님')}</p> : <>
            {counts(signature.evaluation.normal.result!)}<pre>{JSON.stringify(signature.evaluation.normal.reference, null, 2)}</pre>
            <p>{t('Coverage limited; selection asserts normality, it does not prove it.', '제한된 분석 범위입니다. 정상성은 선택자의 판단이며 입증이 아닙니다.')}</p>
          </>}
          <p>{t('Bounded retained observations, not a calibrated attack probability. Packet counts may represent aggregates, not individually inspected packets.', '제한된 보존 관측이며 보정된 공격 확률이 아닙니다. 패킷 수는 개별 검사한 패킷이 아니라 집계 수일 수 있습니다.')}</p>
          <p>{t('Before use: verify target ownership, review normal traffic, obtain human approval.', '사용 전: 대상 소유권 확인, 정상 트래픽 검토, 운영자 승인 필요')} <code>{signature.evaluation.approval_conditions.join(' · ')}</code></p>
          <p>{t('Exclude legitimate shared services and incomplete observations.', '정상 공용 서비스와 불완전 관측을 제외하세요.')} <code>{signature.evaluation.exclusions.join(' · ')}</code></p>
          <p>{t('Invalidate after dataset or topology changes; revalidate before each use.', '데이터셋·토폴로지 변경 시 무효화하고 매 사용 전 재검증하세요.')} <code>{signature.evaluation.invalidation.join(' · ')}</code></p>
        </> : <><p>{t('Legacy candidate: exact predicate evaluation and normal comparison were not recorded.', '이전 버전 후보: 정확한 조건 평가와 정상 비교가 기록되지 않았습니다.')}</p><pre>{JSON.stringify({ protocol: signature.protocol, source_ports: signature.source_ports, destination_ports: signature.destination_ports, packet_size_range: signature.packet_size_range, payload_prefix_hashes: signature.payload_prefix_hashes, tcp_flag_profile: signature.tcp_flag_profile }, null, 2)}</pre></>}
        {signature.evaluation && job && <><p>{t('Passive packet selection (separate v1 export; v4 producer capability remains STRUCTURED_JSON):', '수동 패킷 선택 (별도 v1 내보내기; v4 생산자 기능은 STRUCTURED_JSON 유지):')} {selection?.status === 'EXACT_OFFLINE' ? t('Exact for this same capture and network context only. The JSON includes the BPF expression; no automatic execution.', '동일 캡처·네트워크 문맥에서만 정확합니다. JSON에 BPF 표현식을 포함하며 자동 실행하지 않습니다.') : t('Refused; structured JSON remains available.', '거부됨; 구조화 JSON은 사용 가능합니다.')} {selection && <span>{t(...(filterReasons[selection.reason] ?? ['Unsupported filter condition.', '지원되지 않는 필터 조건입니다.']))} <code>{selection.reason}</code></span>}</p><button type="button" onClick={() => { setExportError(!downloadDDoSExport(report, finding.id, signature.id, job, current)); }}>{t('Download reviewed candidate JSON', '검토용 후보 JSON 다운로드')}</button>{selection?.status === 'EXACT_OFFLINE' && <button type="button" className="secondary" onClick={() => { setExportError(!downloadDDoSExport(report, finding.id, signature.id, job, current, 'BPF')); }}>{t('Download passive BPF v1', '수동 BPF v1 다운로드')}</button>}<p>{t('Filter matches refer to the identical full capture; evaluation counts refer only to bounded retained evidence. Review the capture SHA-256 and internal networks before use. Never apply this as an enforcement rule.', '필터 일치는 동일한 전체 캡처를 대상으로 하며 평가 수치는 제한된 보존 근거만 나타냅니다. 사용 전 캡처 SHA-256과 내부 네트워크를 확인하세요. 차단 규칙으로 적용하지 마세요.')}</p>{exportError && <p role="alert">{t('Export refused: report owner, candidate or byte budget is no longer valid.', '내보내기 거부: 보고서 소유자, 후보 또는 바이트 제한이 유효하지 않습니다.')}</p>}</>}
        <ul>{signature.false_positive_codes.map(code => <li key={code}>{choose(language, falsePositiveCodes[code])}</li>)}</ul>
      </section>}
    </li>; })}</ul>
  </>;
}
