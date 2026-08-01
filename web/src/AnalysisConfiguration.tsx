import { Fragment, type ReactNode } from 'react';

type Configuration = Record<string, unknown>;
type DetectorDefinition = readonly [name: string, label: string, description: string];

type AnalysisConfigurationProps = {
  analysis?: Configuration;
  capture?: Configuration;
  detectorDefinitions: readonly DetectorDefinition[];
  internalNetworks?: string[];
  sensorIds?: string[];
};

const analysisLabels: Record<string, string> = {
  custom_policy: '사용자 정책',
  ml_anomaly_allow_standalone: 'ML 단독 탐지 허용',
  ml_anomaly_enabled: 'ML 이상 탐지',
  minimum_candidate_score: '후보 기준',
  minimum_distinct_clients: '최소 내부 호스트',
  periodicity_min_samples: '주기 판단 최소 표본',
  profile: '분석 프로필',
};

const captureLabels: Record<string, string> = {
  directions: '수집 방향',
  idle_timeout_seconds: '유휴 제한',
  limits: '수집 제한',
  max_bytes: '최대 크기',
  max_duration_seconds: '최대 수집 시간',
  max_packets: '최대 패킷',
  snap_length: '패킷 저장 길이',
  store_pcap: 'PCAP 저장',
};

const knownAnalysisKeys = new Set([
  'profile',
  'minimum_candidate_score',
  'minimum_distinct_clients',
  'periodicity_min_samples',
  'ml_anomaly_enabled',
  'ml_anomaly_allow_standalone',
  'detector_weights',
]);

const isRecord = (value: unknown): value is Configuration =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const titleCase = (value: unknown) => String(value ?? '')
  .replace(/_/g, ' ')
  .replace(/\b\w/g, letter => letter.toUpperCase());

const labelFor = (key: string) => analysisLabels[key] ?? captureLabels[key] ?? titleCase(key);

const formatDuration = (seconds: number) => {
  if (seconds < 60) return `${seconds.toLocaleString()}초`;
  if (seconds % 3600 === 0) return `${(seconds / 3600).toLocaleString()}시간`;
  if (seconds % 60 === 0) return `${(seconds / 60).toLocaleString()}분`;
  return `${seconds.toLocaleString()}초`;
};

const scalar = (value: unknown, key?: string): string => {
  if (value === null || value === undefined || value === '') return '설정되지 않음';
  if (typeof value === 'boolean') return value ? (key === 'store_pcap' ? '사용' : '활성') : '비활성';
  if (typeof value === 'number') {
    if (key?.endsWith('_seconds')) return formatDuration(value);
    return Number.isInteger(value) ? value.toLocaleString() : value.toFixed(2).replace(/0+$/, '').replace(/\.$/, '');
  }
  const text = String(value);
  const identifierField = key && /(?:^|_)(?:id|ids|hash|hashes|network|networks)$/.test(key);
  return identifierField || /[.:/]/.test(text) || text.includes('-') || text === text.toUpperCase() ? text : titleCase(text);
};

function Tags({ values, empty = '설정되지 않음', field }: { values: unknown[]; empty?: string; field?: string }) {
  if (!values.length) return <span className="empty-value">{empty}</span>;
  return <span className="config-tags">{values.map((value, index) => <span className="config-tag" key={`${String(value)}-${index}`}>{scalar(value, field)}</span>)}</span>;
}

export function StructuredValue({ value, field }: { value: unknown; field?: string }): ReactNode {
  if (Array.isArray(value)) {
    const scalarValues = value.filter(item => !isRecord(item) && !Array.isArray(item));
    if (scalarValues.length === value.length) return <Tags values={scalarValues} field={field}/>;
    return <div className="structured-list">{value.map((item, index) => <div key={index}>{isRecord(item) ? <StructuredFields data={item}/> : <StructuredValue value={item}/>}</div>)}</div>;
  }
  if (isRecord(value)) return <StructuredFields data={value}/>;
  return <span className={typeof value === 'boolean' ? `config-state ${value ? 'enabled' : 'disabled'}` : undefined}>{scalar(value, field)}</span>;
}

function StructuredFields({ data }: { data: Configuration }) {
  const entries = Object.entries(data);
  if (!entries.length) return <span className="empty-value">설정 없음</span>;
  return <dl className="structured-fields">{entries.map(([key, value]) => <Fragment key={key}><dt title={key}>{labelFor(key)}</dt><dd><StructuredValue value={value} field={key}/></dd></Fragment>)}</dl>;
}

function SummaryItem({ label, children, tone }: { label: string; children: ReactNode; tone?: string }) {
  return <div className={`config-summary-item${tone ? ` ${tone}` : ''}`}><span>{label}</span><strong>{children}</strong></div>;
}

function WeightStatus({ value }: { value: number }) {
  const status = value === 0 ? '비활성' : value < 1 ? '완화' : value === 1 ? '기본' : '강화';
  const tone = value === 0 ? 'disabled' : value < 1 ? 'reduced' : value === 1 ? 'default' : 'enhanced';
  return <span className={`weight-status ${tone}`}>{status}</span>;
}

export default function AnalysisConfiguration({ analysis = {}, capture = {}, detectorDefinitions, internalNetworks = [], sensorIds = [] }: AnalysisConfigurationProps) {
  const weights = isRecord(analysis.detector_weights) ? analysis.detector_weights : {};
  const detectorMap = new Map(detectorDefinitions.map(definition => [definition[0], definition]));
  const unknownAnalysis = Object.fromEntries(Object.entries(analysis).filter(([key]) => !knownAnalysisKeys.has(key)));
  const profile = analysis.profile;
  const score = analysis.minimum_candidate_score;
  const clients = analysis.minimum_distinct_clients;
  const samples = analysis.periodicity_min_samples;
  const mlEnabled = analysis.ml_anomaly_enabled;

  return <section className="configuration-layout" aria-label="분석 구성">
    <section className="panel capture-settings" aria-label="분석 범위">
      <div className="section-heading"><div><p className="eyebrow">CAPTURE SCOPE</p><h2>분석 범위</h2></div><span className="section-count">{sensorIds.length}개 센서</span></div>
      <div className="scope-block"><span>내부 네트워크</span><Tags values={internalNetworks} empty="지정된 네트워크 없음" field="internal_networks"/></div>
      <div className="scope-block"><span>수집 센서</span><Tags values={sensorIds} empty="지정된 센서 없음" field="sensor_ids"/></div>
      <StructuredFields data={capture}/>
    </section>

    <section className="panel detector-settings" aria-label="탐지 설정 요약">
      <div className="section-heading"><div><p className="eyebrow">DETECTION POLICY</p><h2>탐지 설정</h2></div></div>
      {Object.keys(analysis).length ? <>
        <div className="config-summary-grid">
          <SummaryItem label="분석 프로필">{profile ? <code>{String(profile)}</code> : '기본 프로필'}</SummaryItem>
          <SummaryItem label="최소 후보 점수" tone="primary">{typeof score === 'number' ? `${score.toLocaleString()}점 이상` : '서버 기본값'}</SummaryItem>
          <SummaryItem label="최소 내부 호스트">{typeof clients === 'number' ? `${clients.toLocaleString()}개` : '서버 기본값'}</SummaryItem>
          <SummaryItem label="주기 판단 표본">{typeof samples === 'number' ? `${samples.toLocaleString()}개 이상` : '서버 기본값'}</SummaryItem>
          <SummaryItem label="ML 이상 탐지"><span className={`config-state ${mlEnabled === true ? 'enabled' : 'disabled'}`}>{mlEnabled === true ? '활성' : mlEnabled === false ? '비활성' : '서버 기본값'}</span></SummaryItem>
        </div>

        {Object.keys(weights).length > 0 && <section className="detector-weight-summary" aria-labelledby="detector-weight-heading">
          <div className="subsection-heading"><div><h3 id="detector-weight-heading">탐지기 가중치</h3><p className="muted">1×를 기준으로 탐지 근거가 후보 점수에 반영되는 강도를 표시합니다.</p></div><span className="section-count">{Object.keys(weights).length}개 조정</span></div>
          <div className="weight-summary-grid">{Object.entries(weights).map(([name, rawValue]) => {
            const value = typeof rawValue === 'number' ? rawValue : 1;
            const definition = detectorMap.get(name);
            return <article className="weight-summary-card" key={name} title={name}>
              <div><strong>{definition?.[1] ?? titleCase(name)}</strong><small>{definition?.[2] ?? '사용자 정의 탐지기'}</small></div>
              <div className="weight-value"><strong>{value.toLocaleString(undefined, { maximumFractionDigits: 2 })}×</strong><WeightStatus value={value}/></div>
            </article>;
          })}</div>
        </section>}

        {Object.keys(unknownAnalysis).length > 0 && <section className="advanced-settings"><h3>추가 정책</h3><StructuredFields data={unknownAnalysis}/></section>}
      </> : <div className="empty-state compact"><strong>기록된 탐지 설정이 없습니다</strong><span>이 분석은 Controller 기본 탐지 정책을 사용합니다.</span></div>}
    </section>

    <details className="raw-config-details">
      <summary>원본 설정 보기</summary>
      <p>API가 기록한 값을 확인하거나 지원 요청에 첨부할 때만 사용하세요.</p>
      <pre>{JSON.stringify({ capture, analysis }, null, 2)}</pre>
    </details>
  </section>;
}
