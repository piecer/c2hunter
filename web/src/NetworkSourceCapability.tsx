import { useReportLanguage } from './reportLanguageContext';
import { choose } from './reportTranslations';

type Source = { source_type?: string; mode?: string };
type Selection = 'LIVE' | 'HISTORICAL' | 'PCAP_UPLOAD';
const sensorLimit = ['The current native sensor path does not transmit network packet-evidence. Packet-by-packet TCP/UDP/ICMP patterns and exact RTT, spacing or TTL series cannot be reconstructed from aggregates. Source metadata does not prove every individual record is aggregate; verified positive observations remain valid.', '현재 native 센서 경로는 network packet-evidence를 전달하지 않습니다. 집계에서 패킷별 TCP/UDP/ICMP 패턴과 정확한 RTT·간격·TTL 시계열을 복원할 수 없습니다. 출처 메타데이터가 모든 레코드의 집계 여부를 입증하지는 않으며 검증된 양성 관찰은 유지됩니다.'] as const;
const packetLimit = ['Six supported packet patterns and packet-based supporting measurements can be analyzed, subject to bidirectional visibility, timestamps, fields, protocols, samples and parser/capture limits. PCAP does not guarantee complete coverage or every measurement.', '지원되는 6개 패킷 패턴과 패킷 기반 보조 측정값을 분석할 수 있으나 양방향 관찰·타임스탬프·필드·프로토콜·표본·파서 및 캡처 한도의 조건이 있습니다. PCAP가 완전한 분석 범위나 모든 측정값을 보장하지는 않습니다.'] as const;
const labels = {
  live: ['Sensor LIVE origin', '센서 LIVE 출처'], historical: ['Historical sensor origin', '과거 센서 출처'],
  sensor_reanalysis: ['Sensor-origin reanalysis', '센서 출처 재분석'], pcap: ['Uploaded PCAP origin', '업로드 PCAP 출처'],
  pcap_reanalysis: ['Uploaded-PCAP-origin reanalysis', '업로드 PCAP 출처 재분석'], unknown: ['Unknown source capability', '입력 지원 범위 확인 불가'],
} as const;
export default function NetworkSourceCapability({ source, selection }: { source?: Source; selection?: Selection }) {
  const language = useReportLanguage();
  const text = (pair: readonly [string, string]) => selection ? `${pair[0]} / ${pair[1]}` : choose(language, ...pair);
  const mode = source?.mode;
  const kind = source?.source_type === 'SENSOR_CAPTURE' ? mode === 'LIVE' ? 'live' : mode === 'HISTORICAL' ? 'historical' : mode === 'REANALYSIS' ? 'sensor_reanalysis' : 'unknown' : source?.source_type === 'PCAP_UPLOAD' ? mode === 'PCAP_UPLOAD' ? 'pcap' : mode === 'REANALYSIS' ? 'pcap_reanalysis' : 'unknown' : 'unknown';
  const packet = selection === 'PCAP_UPLOAD' || (!selection && (kind === 'pcap' || kind === 'pcap_reanalysis'));
  const unknown = !selection && kind === 'unknown';
  const title = selection === 'LIVE' ? ['LIVE aggregate input', 'LIVE 집계 입력'] as const : selection === 'HISTORICAL' ? ['Historical sensor aggregates', '과거 센서 집계'] as const : selection === 'PCAP_UPLOAD' ? ['Packet-level PCAP input path', '패킷 수준 PCAP 입력 경로'] as const : labels[kind];
  return <section className="panel compact" aria-label={text(['Source capability', '입력 지원 범위'])}>
    <h3>{text(title)}</h3>
    {unknown ? <p>{text(['Source capability cannot be confirmed. Mode, retained raw bytes, filenames, timing summaries and a packet count of one are not packet-evidence provenance. Verified report observations are shown separately.', '출처 지원 범위를 확인할 수 없습니다. 모드·원시 바이트 보존·파일명·시간 요약·패킷 수 1만으로 패킷 증거 출처를 추정하지 않습니다. 검증된 보고서 관찰은 별도로 표시됩니다.'])}</p> : <>
      {!packet && <p>{text(['Sensor flow and packet/byte aggregate collection.', '센서 흐름 및 패킷·바이트 집계 수집.'])}</p>}
      <p>{text(packet ? packetLimit : sensorLimit)}</p>
      {(selection === 'HISTORICAL' || kind === 'historical') && <p>{text(['Reuses retained sensor flow snapshots; selecting history or changing its time range does not create packet evidence.', '보존된 센서 흐름 스냅샷을 재사용합니다. 과거 선택이나 시간 범위 변경은 패킷 증거를 생성하지 않습니다.'])}</p>}
      {kind === 'sensor_reanalysis' && !selection && <p>{text(['Reanalyzes the same sensor dataset. The original LIVE/HISTORICAL mode is not known from this response.', '같은 센서 데이터셋을 재분석합니다. 이 응답만으로 원래 LIVE/HISTORICAL 모드는 알 수 없습니다.'])}</p>}
      {kind === 'pcap_reanalysis' && !selection && <p>{text(['A new analysis job using retained PCAP source, not a new capture or expanded sensor packet support.', '보존된 PCAP 출처를 사용하는 새 분석 작업이며 새 캡처나 센서 패킷 지원 확장이 아닙니다.'])}</p>}
    </>}
    <p className="muted">{text(['Next passive step: separately analyze an available bidirectional packet-level PCAP with adequate capture coverage. Storing or uploading PCAP does not retroactively enrich this aggregate result.', '다음 수동적 확인: 적절한 양방향 캡처 범위의 사용 가능한 패킷 수준 PCAP를 별도로 분석하세요. PCAP 저장·업로드는 현재 집계 결과를 소급 보강하지 않습니다.'])}</p>
  </section>;
}
