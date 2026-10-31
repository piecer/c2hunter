import { useEffect, useId, useRef, useState } from 'react';
import { useReportLanguage } from './reportLanguageContext';
import { validatePcapGuidanceJob, type GuidanceCandidate, type GuidanceCode, type PcapGuidance } from './pcapAttackGuidance';
import { guidanceText } from './pcapGuidanceTranslations';

type Props = { job: unknown; detailOwner?: string; setDetailOwner?: (owner: string | undefined) => void };
const identities = new WeakMap<object, number>();
let nextIdentity = 0;
function identity(value: object) {
  if (!identities.has(value)) identities.set(value, ++nextIdentity);
  return identities.get(value)!;
}
function Evidence({ candidate: c }: { candidate: GuidanceCandidate }) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => language === 'en' ? en : ko;
  const codes = (items: readonly GuidanceCode[]) => <ul>{items.map(code => <li key={code}>{guidanceText[code][language === 'en' ? 0 : 1]} <code>{code}</code></li>)}</ul>;
  return <section role="region" aria-label={t('Candidate evidence', '후보 근거')}>
    <h4>{t('Observed evidence', '관찰 근거')}</h4>
    <p>{t('Target', '대상')}: <code>{c.target.ip}</code> · {t('Port', '포트')}: {c.target.port ?? t('Not observed', '관찰되지 않음')} · {c.target.protocol}</p>
    <p>{t('Observed role', '관찰 역할')}: {c.role === 'VICTIM_SIDE_INBOUND' ? t('Protected-side inbound', '보호 측 인바운드') : t('Participant-side outbound', '참여 측 아웃바운드')}</p>
    <p>{t('Fixed window (UTC, end exclusive)', '고정 구간 (UTC, 끝 시각 제외)')}: {c.window_start} → {c.window_end}</p>
    <p>{t('Actually observed (UTC)', '실제 관찰 (UTC)')}: {c.first_seen} → {c.last_seen}</p>
    <dl>
      <dt>{t('Packets', '패킷')}</dt><dd>{c.packet_count}</dd><dt>{t('Bytes', '바이트')}</dt><dd>{c.byte_count}</dd>
      <dt>{t('Observed source identities', '관찰 source 식별자')}</dt><dd>{c.source_count}{c.source_count_is_lower_bound ? t(' (lower bound)', ' (하한)') : ''}</dd>
      <dt>{t('SYN-only packets', 'SYN-only 패킷')}</dt><dd>{c.syn_only_count}</dd>
      <dt>{t('ACK-only packets', 'ACK-only 패킷')}</dt><dd>{c.ack_only_count}</dd>
      <dt>{t('RST packets', 'RST 패킷')}</dt><dd>{c.rst_count}</dd>
      <dt>{t('Packets with observed payload', 'payload가 관찰된 패킷')}</dt><dd>{c.payload_packet_count}</dd>
      <dt>{t('Payload visibility complete', 'payload 관찰 범위 완전')}</dt><dd>{c.payload_visibility_complete ? t('Yes', '예') : t('No', '아니요')}</dd>
    </dl>
    <p>{t('Observed source examples — not attacker identities', '관찰 source 예시 — 공격자 신원이 아님')}: {c.source_examples.map((ip, index) => <span key={ip}>{index ? ', ' : ''}<code>{ip}</code></span>)}</p>
    <h4>{t('Why review this window', '이 구간을 검토하는 이유')}</h4>{codes(c.reason_codes)}
    <h4>{t('Within-capture baseline', '캡처 내 기준선')}</h4>
    <p>{t('Earlier occupied windows for this same target:', '같은 대상의 이전 비어 있지 않은 구간:')} {c.baseline_window_count} · {t('Observed baseline packets:', '관찰 기준선 패킷:')} {c.baseline_packet_count}</p>
    <p>{t('This is not known-normal traffic. Only earlier occupied eligible windows in this capture are counted; idle windows are not invented. A zero baseline means unavailable, not zero normal traffic.', '정상으로 확인된 트래픽이 아닙니다. 같은 캡처에서 이전에 관찰된 적격 비어 있지 않은 구간만 집계하며 유휴 구간을 만들지 않습니다. 기준선 0은 사용 불가를 뜻하며 정상 트래픽 0을 뜻하지 않습니다.')}</p>
    <h4>{t('Caveats', '주의 사항')}</h4>{codes(c.uncertainty_codes)}
    <h4>{t('Benign alternatives', '정상 트래픽의 대안 설명')}</h4>{codes(c.alternative_codes)}
    <h4>{t('Passive next checks', '수동 후속 확인')}</h4>{codes(c.next_check_codes)}
  </section>;
}
function OwnedGuidance({ job, guide, signature, detailOwner, setDetailOwner }: Props & { guide: PcapGuidance; signature: string }) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => language === 'en' ? en : ko;
  const [page, setPage] = useState(0);
  const [localOwner, setLocalOwner] = useState<string>();
  const owner = setDetailOwner ? detailOwner : localOwner;
  const setOwner = setDetailOwner ?? setLocalOwner;
  const prefix = useId();
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const current = () => {
    if (!alive.current) return false;
    const result = validatePcapGuidanceJob(job);
    return result.state === 'VALID' && JSON.stringify(result.guide) === signature;
  };
  const s = guide.summary;
  const pages = Math.max(1, Math.ceil(guide.candidates.length / 8));
  const heading = guide.status === 'REVIEW_CANDIDATES' ? t('Additional windows to investigate', '추가로 조사할 구간')
    : guide.status === 'NO_CANDIDATE' ? t('No additional review window retained', '보존된 추가 검토 구간 없음')
      : t('Insufficient observations for window review', '구간 검토를 위한 관찰 부족');
  return <section className="panel pcap-guidance" role="region" aria-label={t('PCAP review guidance', 'PCAP 검토 안내')}>
    <p className="eyebrow">{t('Deterministic offline PCAP review', '결정적 오프라인 PCAP 검토')}</p><h3>{heading}</h3>
    <ul>{guide.limitations.map(code => <li key={code}>{guidanceText[code][language === 'en' ? 0 : 1]}</li>)}</ul>
    <h4>{t('Coverage and omissions', '관찰 범위와 생략')}</h4>
    <p>{s.coverage_complete ? t('Coverage complete for eligible observations; this is not comprehensive attack coverage.', '적격 관찰의 범위는 완전하지만 모든 공격을 평가한 것은 아닙니다.') : t('Coverage is incomplete or qualified; interpret all counts with these limits.', '관찰 범위가 불완전하거나 조건부입니다. 수치를 다음 한계와 함께 해석하세요.')}</p>
    <ul>{guide.coverage_codes.map(code => <li key={code}>{guidanceText[code][language === 'en' ? 0 : 1]} <code>{code}</code></li>)}</ul>
    <p>{t('Retained candidates:', '보존된 후보:')} {s.candidate_count} · {t('Omitted candidates:', '생략된 후보:')} {s.omitted_candidate_count}</p>
    <p>{t('Scanned / evaluated / rejected records:', '검사 / 평가 / 거부 레코드:')} {s.scanned_records} / {s.evaluated_records} / {s.rejected_record_count}</p>
    <p>{t('Observed packets / bytes:', '관찰 패킷 / 바이트:')} {s.packet_count} / {s.byte_count} · {t('Eligible packet observations:', '적격 패킷 관찰:')} {s.eligible_packet_count} · {t('Excluded records:', '제외 레코드:')} {s.excluded_record_count}</p>
    <p>{t('Retained targets / windows:', '보존된 대상 / 구간:')} {s.retained_target_count} / {s.retained_window_count} · {t('Omitted observations:', '생략된 관찰:')} {s.omitted_observation_count}</p>
    <p>{t('Retained SYN/SYN-ACK matching observations / omitted matching observations:', '보존된 SYN/SYN-ACK 매칭 관찰 / 생략된 매칭 관찰:')} {s.response_state_count} / {s.response_omitted_count}</p>
    <p>{t('Qualifying windows / windows suppressed by temporal reply evidence:', '정책 충족 구간 / 시간순 응답 근거로 제외된 구간:')} {s.qualifying_window_count} / {s.suppressed_handshake_window_count}</p>
    <p>{t('Temporal reply evidence is heuristic: it does not prove completed TCP handshakes, successful requests or service health.', '시간순 응답 근거는 휴리스틱이며 TCP handshake 완료, 요청 성공 또는 서비스 정상을 입증하지 않습니다.')}</p>
    <p>{t('Observed capture bounds (UTC):', '관찰 캡처 범위 (UTC):')} {s.first_seen ?? t('Unavailable', '사용 불가')} → {s.last_seen ?? t('Unavailable', '사용 불가')}</p>
    <p>{t('Before any response, preserve the capture and correlate target/time with existing service logs. These checks do not execute mitigation.', '대응 전 캡처를 보존하고 대상·시각을 기존 서비스 로그와 대조하세요. 이 확인 절차는 완화 조치를 실행하지 않습니다.')}</p>
    {guide.candidates.slice(page * 8, page * 8 + 8).map((c, offset) => {
      const index = page * 8 + offset, key = `${prefix}:${index}`, open = owner === key;
      return <article className="panel compact" key={index}>
        <h4>{guidanceText[c.family][language === 'en' ? 0 : 1]}</h4>
        <p><code>{c.target.ip}</code> · {c.target.port ?? '—'} · {c.target.protocol} · {c.packet_count} {t('observed packets', '관찰 패킷')}</p>
        <p>{c.first_seen} → {c.last_seen}</p>
        <p>{guidanceText[c.reason_codes[0]][language === 'en' ? 0 : 1]}</p>
        <button type="button" aria-expanded={open} aria-controls={open ? key : undefined} onClick={() => { if (current()) setOwner(open ? undefined : key); }}>{t('Review window', '검토 구간')} {index + 1}</button>
        {open && <div id={key}><Evidence candidate={c}/></div>}
      </article>;
    })}
    {guide.candidates.length > 0 && <nav aria-label={t('Review candidate pages', '검토 후보 페이지')}>
      <button type="button" disabled={page === 0} onClick={() => { if (current()) { setPage(page - 1); setOwner(undefined); } }}>{t('Previous candidate page', '이전 후보 페이지')}</button>
      <span role="status" aria-live="polite">{t(`Page ${page + 1} of ${pages}`, `${pages}페이지 중 ${page + 1}페이지`)}</span>
      <button type="button" disabled={page + 1 >= pages} onClick={() => { if (current()) { setPage(page + 1); setOwner(undefined); } }}>{t('Next candidate page', '다음 후보 페이지')}</button>
    </nav>}
  </section>;
}
export function PcapGuidanceAIScope() {
  const language = useReportLanguage();
  return <p className="muted">{language === 'en' ? 'Optional AI interprets existing DDoS findings only, not these review candidates. It is not the guidance detector.' : '선택적 AI는 기존 DDoS 발견 항목만 해석하며 이 검토 후보를 해석하지 않습니다. 검토 안내 탐지기가 아닙니다.'}</p>;
}

export default function PcapAttackGuidance(props: Props) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => language === 'en' ? en : ko;
  const result = validatePcapGuidanceJob(props.job);
  if (result.state === 'INVALID') return <section className="panel" role="alert"><h3>{t('Invalid PCAP review guidance', '잘못된 PCAP 검토 안내')}</h3><p>{t('The present artifact failed validation and was not displayed. This is not a clean result; the existing DDoS report remains separate.', '존재하는 산출물이 검증을 통과하지 못해 표시하지 않습니다. 정상 결과가 아니며 기존 DDoS 보고서와 별개입니다.')}</p></section>;
  if (result.state === 'UNAVAILABLE') return <section className="panel"><h3>{t('PCAP review guidance unavailable', 'PCAP 검토 안내 사용 불가')}</h3><p>{t('Review guidance was not generated for this job. Absence is not evidence of clean traffic.', '이 작업의 검토 안내가 생성되지 않았습니다. 부재는 정상 트래픽의 증거가 아닙니다.')}</p></section>;
  const signature = JSON.stringify(result.guide);
  return <OwnedGuidance {...props} key={`${identity(props.job as object)}:${signature}`} guide={result.guide} signature={signature}/>;
}
