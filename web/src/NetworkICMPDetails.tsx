import { useState } from 'react';
import type { ICMPResult } from './networkICMPDetails';
import { useReportLanguage } from './reportLanguageContext';
import { choose } from './reportTranslations';

// One event from one representative at a time; no hidden mounted event history.
export default function NetworkICMPDetails({ values }: { values: (ICMPResult | undefined)[] }) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => choose(language, en, ko);
  const [open, setOpen] = useState(false), [example, setExample] = useState(0), [event, setEvent] = useState(0);
  const detail = values[example];
  const value = detail?.state === 'valid' ? detail.value : undefined;
  const sample = value?.samples[event];
  const endpoint = (ip: string | null, port: number | null) => `${ip === null ? t('unknown', '알 수 없음') : ip.includes(':') ? `[${ip}]` : ip}${port === null ? '' : `:${port}`}`;
  return <section aria-label={t('ICMP reporter evidence', 'ICMP 보고 장치 근거')}>
    <button type="button" aria-expanded={open} onClick={() => setOpen(!open)}>{t('ICMP event details', 'ICMP 이벤트 상세')}</button>
    {open && <>
      <p>{t('The outer reporter sent this error; it is not a proven fault location. Quoted flow direction is preserved. Review retained evidence and device policy; this is not an active network diagnosis.', '외부 보고 장치가 이 오류를 보냈지만 장애 위치로 확정된 것은 아닙니다. 인용 흐름의 방향을 보존합니다. 보존된 증거와 장치 정책을 확인하세요. 능동 네트워크 진단이 아닙니다.')}</p>
      <nav aria-label={t('ICMP representative pages', 'ICMP 대표 예시 페이지')}>
        <button disabled={example === 0} onClick={() => { setExample(example-1); setEvent(0); }}>{t('Previous representative', '이전 대표 예시')}</button>
        <span role="status">{example+1} / {values.length}</span>
        <button disabled={example+1 >= values.length} onClick={() => { setExample(example+1); setEvent(0); }}>{t('Next representative', '다음 대표 예시')}</button>
      </nav>
      {!value && <p role={detail?.state === 'invalid' ? 'alert' : undefined}>{detail?.state === 'invalid' ? t('Invalid ICMP details; valid raw facts remain available.', '잘못된 ICMP 상세입니다. 유효한 원래 사실은 계속 제공됩니다.') : t('ICMP details were not recorded; reporters and detail omissions are unknown.', 'ICMP 상세가 기록되지 않아 보고 장치와 상세 생략 수를 알 수 없습니다.')}</p>}
      {value && <>
        <p>{value.samples.length} {t('retained event details', '개 보존 이벤트 상세')} · {value.omitted_event_details} {t('event details omitted (not detections, groups or examples). First admitted samples only; later reporters may be omitted.', '개 이벤트 상세 생략 (탐지·그룹·예시 수가 아님). 최초 수용 표본만 보존하며 뒤쪽 보고 장치는 생략될 수 있습니다.')}</p>
        {sample && <>
          <p>{t('Outer reporter', '외부 보고 장치')}: {sample.reporter_ip} · {sample.protocol} · {t('type / code', '유형 / 코드')}: {sample.type} / {sample.code}</p>
          <p>{t('Event time', '이벤트 시간')}: {sample.time}</p>
          <p>{t('Quoted flow (source → destination)', '인용 흐름 (출발지 → 목적지)')}: {sample.quoted_flow ? `${endpoint(sample.quoted_flow.source_ip,sample.quoted_flow.source_port)} → ${endpoint(sample.quoted_flow.destination_ip,sample.quoted_flow.destination_port)} · ${sample.quoted_flow.protocol ?? t('unknown','알 수 없음')}` : t('Unknown / unavailable; no target is inferred.', '알 수 없음 / 미제공. 대상을 추정하지 않습니다.')}</p>
          <p>{t('Packet reference unavailable: this path has no capture-bound packet authority.', '패킷 참조 미제공: 이 경로에는 캡처에 결속된 패킷 참조 근거가 없습니다.')}</p>
        </>}
        {value.samples.length > 1 && <nav aria-label={t('ICMP event pages', 'ICMP 이벤트 페이지')}>
          <button disabled={event === 0} onClick={() => setEvent(event-1)}>{t('Previous event detail', '이전 이벤트 상세')}</button><span role="status">{event+1} / {value.samples.length}</span>
          <button disabled={event+1 >= value.samples.length} onClick={() => setEvent(event+1)}>{t('Next event detail', '다음 이벤트 상세')}</button>
        </nav>}
      </>}
    </>}
  </section>;
}
