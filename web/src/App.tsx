import { Fragment, FormEvent, ReactNode, useEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, Navigate, NavLink, Route, Routes, useNavigate, useParams } from 'react-router-dom';
import { api } from './api';
import './styles.css';

type Page<T> = { items: T[]; page?: number; page_size?: number; total?: number };
type List<T> = Page<T> | T[];
const items = <T,>(value?: List<T>) => Array.isArray(value) ? value : value?.items ?? [];
const fmt = (value?: string) => value ? new Date(value).toLocaleString() : 'Not reported';
const formatBytes = (value?: number) => {
  if (value === undefined) return 'Unknown size';
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
};

type CaptureSource = { interface: string; name?: string; direction: string; bpf_filter: string; enabled: boolean; status?: string; received_packets?: number; dropped_packets?: number; last_error?: string };
type SensorConfiguration = { version?: number; capture_sources: CaptureSource[]; internal_networks: string[] };
type Sensor = { sensor_id: string; name: string; status?: string; derived_status?: string; last_heartbeat?: string; last_heartbeat_at?: string; interfaces?: { name: string; direction: string }[]; observed_interfaces?: CaptureSource[]; capture_sources?: CaptureSource[]; internal_networks?: string[]; config_version?: number; version?: string; agent_version?: string; configuration_version?: number; desired_configuration?: SensorConfiguration; observed_configuration?: SensorConfiguration; cpu_percent?: number; memory_percent?: number; disk_percent?: number; received_packets?: number; dropped_packets?: number; last_error?: string };
type Enrollment = { id?: string; enrollment_id?: string; name: string; status: 'PENDING' | 'CLAIMED' | 'EXPIRED' | 'REVOKED'; expires_at: string; sensor_id?: string };
type EnrollmentSecret = { enrollment_token: string; install_command: string; expires_at: string };
type JobSource = { filename?: string; capture_format?: string; size_bytes?: number; sha256?: string; captured_packet_count?: number; parsed_packet_count?: number; skipped_packet_count?: number; link_types?: number[] };
type JobTransition = { from_status?: string; to_status: string; occurred_at?: string; reason?: string };
type Job = { id: string; dataset_id?: string; parent_job_id?: string; name: string; description?: string; status: string; mode?: string; source_type?: string; source?: JobSource; created_at?: string; updated_at?: string; completed_at?: string; start_time?: string; end_time?: string; sensor_ids?: string[]; internal_networks?: string[]; capture?: Record<string, unknown>; analysis?: Record<string, unknown>; transitions?: JobTransition[]; progress_percent?: number; packet_count?: number; flow_count?: number; candidate_count?: number; warnings?: string[] };
type Evidence = { type: string; detector?: string; version?: string; raw_score?: number; contribution?: number; score?: number; description?: string; hosts?: string[]; sensors?: string[]; first_seen?: string; last_seen?: string; metrics?: Record<string, unknown>; confidence?: number; warnings?: string[] };
type ScoreAdjustment = { kind: string; points: number; explanation: string };
type TrafficBucket = { start: string; packets: number; bytes: number; flows: number };
type Candidate = { id: string; job_id?: string; candidate_ip: string; score: number; severity: string; distinct_internal_hosts?: number; hosts?: string[]; internal_hosts?: string[]; sensors?: string[]; sensor_ids?: string[]; protocols?: string[]; ports?: number[]; domains?: string[]; first_seen?: string; last_seen?: string; evidence?: Evidence[]; evidence_count?: number; adjustments?: ScoreAdjustment[]; traffic_series?: number[]; traffic_buckets?: TrafficBucket[]; related_attack_targets?: string[]; flow_count?: number; packet_count?: number; byte_count?: number };
type FlowLabel = { id: string; verdict: 'C2' | 'BENIGN'; confidence: 'CONFIRMED' | 'HIGH' | 'MEDIUM'; note: string; created_by?: string; created_at: string };
type FlowRecordReview = { flow_id: string; job_id: string; sensor_id?: string; timestamp: string; source_ip: string; destination_ip: string; source_port?: number; destination_port?: number; internal_ip?: string; external_ip?: string; service_port?: number; protocol: string; direction: string; packet_count?: number; total_bytes?: number; payload_hash?: string; payload_prefix_hash?: string; payload_length?: number; payload_entropy?: number; payload_printable_ratio?: number; payload_simhash?: string; payload_feature_version?: string; has_payload: boolean; current_label?: FlowLabel | null };
type PayloadPreview = { flow_id: string; payload_hex: string; payload_ascii: string; sample_bytes: number; payload_length?: number; truncated: boolean; payload_hash?: string };
type PayloadSignature = { id: string; name: string; description?: string; version: number; enabled: boolean; source_job_id: string; source_flow_id: string; source_label_id: string; protocol?: string; direction?: string; service_port?: number; payload_hash?: string; payload_prefix_hash?: string; payload_length?: number; payload_entropy?: number; payload_printable_ratio?: number; payload_simhash?: string; payload_feature_version?: string; length_tolerance_ratio: number; entropy_tolerance: number; simhash_max_distance: number; created_by?: string; created_at: string; updated_at?: string };
type DetectionCondition = { evidence_type: string; detector: string; contribution: number; weighted_contribution: number; description: string; metrics: Record<string, unknown> };
type DetectionRecommendation = { id?: string; kind: string; detector?: string; current_value?: number; recommended_value?: number; projected_score: number; score_gain: number; rationale: string; risk: string; risk_note: string; reanalysis?: { minimum_candidate_score: number; detector_weights: DetectorWeights } };
type DetectionGuidance = { flow_id: string; candidate_ip: string; initially_detected: boolean; suppressed_by_policy: boolean; current_score: number; minimum_candidate_score: number; score_gap: number; conditions: DetectionCondition[]; adjustments: ScoreAdjustment[]; recommendations: DetectionRecommendation[]; recommended_reanalysis?: { minimum_candidate_score: number; detector_weights: DetectorWeights } | null; warnings: string[] };
type AllowEntry = { id: string; type: string; value: string; description?: string; expires_at?: string };
const PCAP_UPLOAD_MAX_BYTES = 500 * 1024 * 1024;
type DetectorWeights = Record<string, number>;
type DetectorWeightPreset = { id: string; name: string; description?: string; detector_weights: DetectorWeights; is_default: boolean };
const detectorDefinitions = [
  ['common_destination', '공통 목적지', '여러 내부 호스트가 같은 외부 목적지와 통신하는 패턴'],
  ['non_well_known_port', '비표준 포트', '높은 서비스 포트를 반복 사용하는 외부 통신'],
  ['periodic_beacon', '주기 통신', '일정한 간격으로 반복되는 비콘 통신'],
  ['single_host_composite_beacon', '단일 호스트 비콘', '한 호스트에서 지속되는 안정적인 저용량 비콘'],
  ['analyst_payload_signature', '분석가 페이로드 서명', '분석가가 확인한 악성 페이로드와의 일치'],
  ['synchronized_communication', '동기화 통신', '여러 호스트가 비슷한 시점에 반복 통신하는 패턴'],
  ['command_attack_correlation', '명령·공격 연관성', '명령 통신 이후 발생한 공격 활동의 연관성'],
  ['persistence_rarity', '희소 지속 통신', '드문 외부 대상과 장기간 유지되는 저용량 통신'],
  ['protocol_similarity', '프로토콜 유사성', '여러 호스트가 공유하는 프로토콜·페이로드 특성'],
  ['multi_sensor_context', '다중 센서 관측', '여러 센서에서 독립적으로 관측된 외부 대상'],
  ['ml_population_anomaly', '모집단 이상', '동일 분석의 다른 후보와 비교해 이례적인 통신 특성'],
] as const;
const detectorLabels = Object.fromEntries(detectorDefinitions.map(([name, label]) => [name, `${label} 탐지기`])) as Record<string, string>;
const evidenceLabels: Record<string, string> = {
  COMMON_DESTINATION: '공통 목적지',
  NON_WELL_KNOWN_PORT: '비표준 포트 사용',
  PERIODIC_BEACON: '주기적 비콘',
  SINGLE_HOST_BEACON: '단일 호스트 비콘',
  ANALYST_PAYLOAD_SIGNATURE: '분석가 페이로드 서명 일치',
  SYNCHRONIZED_COMMUNICATION: '동기화 통신',
  COMMAND_ATTACK_CORRELATION: '명령·공격 연관성',
  LOW_VOLUME_PERSISTENCE_RARITY: '희소 저용량 지속 통신',
  PROTOCOL_PAYLOAD_SIMILARITY: '프로토콜·페이로드 유사성',
  MULTI_SENSOR_CONTEXT: '다중 센서 관측',
  ML_POPULATION_ANOMALY: '모집단 이상',
};
const metricLabels: Record<string, string> = {
  action: '처리 방식', affected_hosts: '영향 호스트', analyst_confirmed: '분석가 확인', anomaly_score: '이상 점수', attack_target: '공격 대상', autocorrelation: '자기상관', available_feature_count: '사용 가능 특성 수', average_packets: '평균 패킷 수', baseline_population: '기준 모집단', cdn_cloud: 'CDN·클라우드 여부', coefficient_of_variation: '변동계수', command_size: '명령 크기', comparable_features: '비교 가능 특성', comparisons: '비교 결과', connections: '연결 수', connections_per_host: '호스트당 연결 수', destination_stability: '목적지 안정성', directional_feature_count: '방향별 특성 수', directional_z_score: '방향별 Z 점수', directional_z_scores: '방향별 Z 점수 목록', distinct_domains: '고유 도메인 수', distinct_hosts: '고유 호스트 수', distinct_sensors: '고유 센서 수', domain_diversity: '도메인 다양성', domain_diversity_ratio: '도메인 다양성 비율', dominant_feature_ratio: '주요 특성 비율', dominant_port: '주요 포트', dominant_port_ratio: '주요 포트 비율', duration_seconds: '지속 시간(초)', entropy_difference: '엔트로피 차이', entropy_tolerance: '엔트로피 허용치', event_count: '이벤트 수', feature: '특성', feature_vector: '특성 벡터', feature_z_floor: '특성 Z 점수 하한', fingerprint_ratio: '지문 일치 비율', fingerprint_stability: '지문 안정성', flow_payload_hashes: '흐름 페이로드 해시', increase_ratio: '증가 비율', independent_hosts: '독립 호스트 수', interval_cv: '통신 간격 변동계수', jitter_ratio: '지터 비율', length_difference: '길이 차이', length_tolerance: '길이 허용치', match_mode: '일치 방식', matched_flow_count: '일치 흐름 수', matched_payload_hash: '일치 페이로드 해시', matched_payload_position: '일치 페이로드 위치', matching_hosts: '일치 호스트 수', minimum_feature_population: '최소 특성 모집단', non_well_known_ratio: '비표준 포트 비율', observation_count: '관측 수', observed_flow_count: '관측 흐름 수', observed_spread: '관측 분산', payload_hash: '페이로드 해시', payload_stability: '페이로드 안정성', period_seconds: '주기(초)', population_size: '모집단 크기', port_stability: '포트 안정성', prefix_match: '접두부 일치', public_dns_ntp: '공용 DNS·NTP 여부', rarity: '희소도', raw_z_scores: '원시 Z 점수', repetition_count: '반복 횟수', sample_count: '표본 수', service_port: '서비스 포트', service_ports: '서비스 포트 목록', signature_id: '서명 ID', signature_name: '서명 이름', signature_version: '서명 버전', simhash_distance: 'SimHash 거리', simhash_max_distance: 'SimHash 최대 거리', size_coefficient_of_variation: '크기 변동계수', size_cv: '크기 변동계수', size_similarity: '크기 유사도', synchronized_hosts: '동기화 호스트 수', target_port: '대상 포트', target_protocol: '대상 프로토콜', timestamp_tolerance_seconds: '시각 허용 범위(초)', top_contributing_features: '주요 기여 특성', well_known_port_max: '표준 포트 상한', window_seconds: '관측 구간(초)', z_threshold: 'Z 점수 임계값',
};
const fieldLabels: Record<string, string> = { profile: '분석 프로필', minimum_candidate_score: '최소 후보 점수', detector_weights: '탐지기 가중치' };
const adjustmentLabels: Record<string, string> = { SINGLE_HOST: '단일 호스트 감점', LOW_SAMPLE: '표본 부족 감점', PUBLIC_DNS_NTP: '공용 DNS·NTP 감점', CDN_CLOUD: 'CDN·클라우드 감점', HIGH_VOLUME: '대용량 통신 감점' };
const evidenceLabel = (type?: string) => type ? evidenceLabels[type] ?? '사용자 정의 탐지 근거' : '탐지 근거';
const detectorLabel = (name?: string) => name ? detectorLabels[name] ?? '사용자 정의 탐지기' : '알 수 없는 탐지기';
const metricLabel = (name: string) => metricLabels[name] ?? '세부 지표';
const fieldLabel = (name: string) => fieldLabels[name] ?? humanize(name);
const adjustmentLabel = (value: unknown) => {
  const kind = String(value ?? '');
  return kind.startsWith('DETECTOR_WEIGHT_') ? `${evidenceLabel(kind.replace('DETECTOR_WEIGHT_', ''))} 가중치` : adjustmentLabels[kind] ?? '점수 조정';
};
const localizedMetricValue = (value: unknown) => {
  const labels: Record<string, string> = { EXACT: '정확 일치', STRUCTURAL: '구조 유사', FIRST: '첫 페이로드', LAST: '마지막 페이로드', alert: '경고', monitor: '관찰', HIGH: '높음', LOW: '낮음' };
  return typeof value === 'string' && labels[value] ? labels[value] : formatValue(value);
};
const defaultDetectorWeights = Object.fromEntries(detectorDefinitions.map(([name]) => [name, 1])) as DetectorWeights;
const serviceNoiseDetectorWeights = {
  ...defaultDetectorWeights,
  common_destination: 0.25,
  synchronized_communication: 0.5,
  protocol_similarity: 0.5,
  multi_sensor_context: 0.5,
  ml_population_anomaly: 0.5,
};
const normalizedDetectorWeights = (weights?: DetectorWeights): DetectorWeights => detectorDefinitions.reduce<DetectorWeights>((result, [name]) => {
  const value = weights?.[name];
  result[name] = typeof value === 'number' && value >= 0 && value <= 2 ? value : 1;
  return result;
}, {});
const sensorStatus = (sensor: Sensor) => sensor.status ?? sensor.derived_status ?? 'OFFLINE';
let idempotencySequence = 0;
const idempotencyKey = () => {
  idempotencySequence += 1;
  const randomPart = globalThis.crypto?.randomUUID?.() ?? `${idempotencySequence}-${Math.random().toString(36).slice(2)}`;
  return `${Date.now()}-${randomPart}`;
};
const terminalStatuses = new Set(['COMPLETED', 'PARTIALLY_COMPLETED', 'FAILED', 'CANCELLED']);
const strings = (value?: string[]) => Array.isArray(value) ? value : [];
const numbers = (value?: number[]) => Array.isArray(value) ? value : [];
const candidateHosts = (candidate: Candidate) => strings(candidate.internal_hosts ?? candidate.hosts);
const candidateSensors = (candidate: Candidate) => strings(candidate.sensor_ids ?? candidate.sensors);
const candidateEvidence = (candidate: Candidate) => Array.isArray(candidate.evidence) ? candidate.evidence : [];
const humanize = (value: unknown) => String(value ?? '').replace(/_/g, ' ').replace(/\b\w/g, letter => letter.toUpperCase());
const formatValue = (value: unknown): string => {
  if (value === null || value === undefined || value === '') return 'Not reported';
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (typeof value === 'number') return Number.isInteger(value) ? value.toLocaleString() : value.toFixed(3).replace(/0+$/, '').replace(/\.$/, '');
  if (Array.isArray(value)) return value.length ? value.map(formatValue).join(', ') : 'None';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
};

function DetectorWeightFields({ weights, setWeights, applyDefault = true }: { weights: DetectorWeights; setWeights: (value: DetectorWeights) => void; applyDefault?: boolean }) {
  const queryClient = useQueryClient();
  const presets = useQuery<List<DetectorWeightPreset>, Error>({ queryKey: ['detector-weight-presets'], queryFn: () => api.get('/detector-weight-presets') });
  const [selectedPreset, setSelectedPreset] = useState('');
  const [presetName, setPresetName] = useState('');
  const [saveAsDefault, setSaveAsDefault] = useState(false);
  const [isExplicit, setIsExplicit] = useState(false);
  const appliedDefault = useRef(false);
  const markExplicit = () => { appliedDefault.current = true; setIsExplicit(true); };
  const savePreset = useMutation<DetectorWeightPreset, Error, { name: string; detector_weights: DetectorWeights; set_as_default: boolean }>({
    mutationFn: body => api.post('/detector-weight-presets', body),
    onSuccess: preset => {
      setPresetName(''); setSaveAsDefault(false); setSelectedPreset(preset.id);
      queryClient.invalidateQueries({ queryKey: ['detector-weight-presets'] });
    },
  });
  const setDefaultPreset = useMutation<DetectorWeightPreset, Error, string>({
    mutationFn: presetId => api.patch(`/detector-weight-presets/${presetId}`, { set_as_default: true }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['detector-weight-presets'] }),
  });
  useEffect(() => {
    if (!applyDefault || appliedDefault.current || !presets.data) return;
    appliedDefault.current = true;
    const preset = items(presets.data).find(item => item.is_default);
    if (preset) { setSelectedPreset(preset.id); setWeights(normalizedDetectorWeights(preset.detector_weights)); }
  }, [applyDefault, presets.data, setWeights]);
  const selectPreset = (presetId: string) => {
    markExplicit();
    setSelectedPreset(presetId);
    const preset = items(presets.data).find(item => item.id === presetId);
    if (preset) setWeights(normalizedDetectorWeights(preset.detector_weights));
  };
  return <fieldset className="detector-weights">{isExplicit && <input type="hidden" name="detector_weights_explicit" value="true"/>}<legend>탐지 점수 가중치</legend><p className="muted">0은 점수 반영 안 함, 1은 기본값, 2는 두 배 반영을 뜻합니다. 탐지 근거는 감사 목적으로 계속 표시됩니다.</p>{presets.error && <p aria-live="polite" className="error-text">프리셋 불러오기 실패: {presets.error.message}</p>}<div className="grid"><label>저장된 탐지 가중치 프리셋<select value={selectedPreset} onChange={event => selectPreset(event.target.value)}><option value="">사용자 지정 가중치</option>{items(presets.data).map(preset => <option key={preset.id} value={preset.id}>{preset.name}{preset.is_default ? ' (기본)' : ''}</option>)}</select></label><label>새 프리셋 이름<input value={presetName} maxLength={200} onChange={event => setPresetName(event.target.value)}/></label><label className="check"><input type="checkbox" checked={saveAsDefault} onChange={event => setSaveAsDefault(event.target.checked)}/>기본 프리셋으로 저장</label></div><div className="actions"><button type="button" className="secondary" onClick={() => { markExplicit(); setSelectedPreset(''); setWeights({ ...defaultDetectorWeights }); }}>탐지 가중치 초기화</button><button type="button" className="secondary" onClick={() => { markExplicit(); setSelectedPreset(''); setWeights({ ...serviceNoiseDetectorWeights }); }}>대형 서비스 노이즈 줄이기</button><button type="button" className="secondary" disabled={!presetName.trim() || savePreset.isPending} onClick={() => savePreset.mutate({ name: presetName.trim(), detector_weights: weights, set_as_default: saveAsDefault })}>현재 가중치 저장</button><button type="button" className="secondary" disabled={!selectedPreset || setDefaultPreset.isPending} onClick={() => setDefaultPreset.mutate(selectedPreset)}>선택 프리셋을 기본값으로</button></div>{(savePreset.error || setDefaultPreset.error) && <p role="alert" className="error-text">{(savePreset.error || setDefaultPreset.error)?.message}</p>}<div className="weight-grid">{detectorDefinitions.map(([name, label, description]) => <label key={name}><span>{label}<small>{description}</small></span><input name={`weight_${name}`} aria-label={`${label} 가중치`} type="number" min="0" max="2" step="0.05" value={weights[name] ?? 1} onChange={event => { markExplicit(); setSelectedPreset(''); setWeights({ ...weights, [name]: Number(event.target.value) }); }}/></label>)}</div></fieldset>;
}

function AsyncState<T>({ query, children, empty }: { query: ReturnType<typeof useQuery<T, Error>>; children: (data: T) => ReactNode; empty?: (data: T) => boolean }) {
  if (query.isLoading) return <div className="state" role="status" aria-live="polite"><span className="spinner"/> Loading…</div>;
  if (query.isError) return <div className="state error" role="alert"><strong>Unable to load data</strong><p>{query.error.message}</p><button onClick={() => query.refetch()}>Retry</button></div>;
  if (query.data && empty?.(query.data)) return <div className="state">No data available</div>;
  return query.data ? <>{children(query.data)}</> : null;
}

function Login() {
  const [username, setUsername] = useState('analyst'); const [error, setError] = useState('');
  const login = async (event: FormEvent) => { event.preventDefault(); setError(''); try { const result = await api.post<{ access_token: string }>('/auth/dev-login', { username }); localStorage.setItem('c2hunter-token', result.access_token); window.location.assign('/'); } catch (e) { setError(e instanceof Error ? e.message : 'Login failed'); } };
  return <main className="login"><form className="panel" onSubmit={login}><div className="brand">C2<span>Hunter</span></div><h1>Defensive analysis console</h1><p className="muted">Development login is enabled only when the Controller explicitly permits it.</p><label>Username<input value={username} onChange={e => setUsername(e.target.value)} required /></label>{error && <p role="alert" className="error-text">{error}</p>}<button type="submit">Development login</button></form></main>;
}

function Shell({ children }: { children: ReactNode }) {
  const navigate = useNavigate();
  return <div className="shell"><aside><div className="brand">C2<span>Hunter</span></div><nav aria-label="Primary"><NavLink end to="/">Dashboard</NavLink><NavLink to="/sensors">Sensors</NavLink><NavLink to="/external-sensors">External sensors</NavLink><NavLink className="nav-child" to="/external-sensors/enroll">Enroll sensor</NavLink><NavLink to="/analyses">Analysis history</NavLink><NavLink className="nav-child" to="/analyses/new">New analysis</NavLink><NavLink className="nav-child" to="/analyses/upload">Upload PCAP</NavLink><NavLink to="/candidates">Candidates</NavLink><NavLink to="/payload-signatures">Payload signatures</NavLink><NavLink to="/allowlist">Allowlist</NavLink></nav><button className="quiet" onClick={() => { localStorage.removeItem('c2hunter-token'); navigate('/login'); }}>Sign out</button></aside><main className="content">{children}</main></div>;
}

function Dashboard() {
  const query = useQuery<Record<string, number | number[]>, Error>({
    queryKey: ['dashboard'],
    queryFn: async () => {
      const [sensorData, jobData] = await Promise.all([
        api.get<List<Sensor>>('/sensors'),
        api.get<List<Job>>('/analysis-jobs'),
      ]);
      const sensors = items(sensorData);
      const jobs = items(jobData);
      return {
        online_sensors: sensors.filter(sensor => sensorStatus(sensor) !== 'OFFLINE').length,
        offline_sensors: sensors.filter(sensor => sensorStatus(sensor) === 'OFFLINE').length,
        capturing_jobs: jobs.filter(job => ['CAPTURING', 'UPLOADING', 'INGESTING', 'ANALYZING'].includes(job.status)).length,
        recent_analyses: jobs.length,
        high_critical_candidates: jobs.reduce((total, job) => total + (job.candidate_count ?? 0), 0),
        candidate_trend: jobs.slice(-24).map(job => job.candidate_count ?? 0),
      };
    },
  });
  return <><header><p className="eyebrow">OPERATIONS OVERVIEW</p><h1>Dashboard</h1></header><AsyncState query={query}>{d => <><section className="metrics">{[['Online sensors', d.online_sensors], ['Offline sensors', d.offline_sensors], ['Capturing jobs', d.capturing_jobs], ['Recent analyses', d.recent_analyses], ['High / critical', d.high_critical_candidates]].map(([label, value]) => <article className="metric" key={String(label)}><span>{label}</span><strong>{String(value ?? 0)}</strong></article>)}</section><section className="panel"><h2>Candidate trend · 24h</h2><MiniChart values={(d.candidate_trend as number[]) ?? []} label="Candidates in the last 24 hours" /></section></>}</AsyncState></>;
}

function MiniChart({ values, label }: { values: number[]; label: string }) {
  const max = Math.max(...values, 1); const points = values.map((v, i) => `${i * (300 / Math.max(1, values.length - 1))},${100 - v / max * 90}`).join(' ');
  return <svg className="chart" viewBox="0 0 300 110" role="img" aria-label={label}><title>{label}</title><polyline points={points} fill="none" stroke="currentColor" strokeWidth="3"/><line x1="0" y1="100" x2="300" y2="100" /></svg>;
}

function Sensors() {
  const query = useQuery<List<Sensor>, Error>({ queryKey: ['sensors'], queryFn: () => api.get('/sensors') });
  return <><header><p className="eyebrow">FLEET</p><h1>Sensors</h1></header><AsyncState query={query} empty={d => items(d).length === 0}>{d => <div className="table-wrap"><table aria-label="Sensors"><thead><tr><th>Sensor</th><th>Status</th><th>Heartbeat</th><th>Interface / direction</th><th>Drops</th></tr></thead><tbody>{items(d).map(s => <tr key={s.sensor_id}><td><Link to={`/sensors/${s.sensor_id}`}>{s.name}</Link><small>{s.sensor_id}</small></td><td><span className={`badge ${sensorStatus(s).toLowerCase()}`}>{sensorStatus(s)}</span></td><td>{fmt(s.last_heartbeat ?? s.last_heartbeat_at)}</td><td>{s.interfaces?.map(i => <span key={i.name}>{i.name} <code>{i.direction}</code></span>)}</td><td>{s.dropped_packets ?? 0}</td></tr>)}</tbody></table></div>}</AsyncState></>;
}

function SensorDetail() {
  const { id } = useParams();
  const q = useQuery<Sensor, Error>({ queryKey: ['sensor', id], queryFn: () => api.get(`/sensors/${id}`) });
  return <AsyncState query={q}>{s => { const desired = s.desired_configuration ?? (s.capture_sources && s.internal_networks ? { version: s.config_version, capture_sources: s.capture_sources, internal_networks: s.internal_networks } : undefined); const observed = s.observed_configuration ?? (s.observed_interfaces ? { version: s.config_version, capture_sources: s.observed_interfaces, internal_networks: s.internal_networks ?? [] } : undefined); const configured = { ...s, desired_configuration: desired, observed_configuration: observed }; return <><header><p className="eyebrow">SENSOR DETAIL</p><h1>{s.name}</h1><span className={`badge ${sensorStatus(s).toLowerCase()}`}>{sensorStatus(s)}</span></header><section className="grid"><article className="panel"><h2>Resources</h2><dl><dt>CPU</dt><dd>{s.cpu_percent ?? 0}%</dd><dt>Memory</dt><dd>{s.memory_percent ?? 0}%</dd><dt>Disk</dt><dd>{s.disk_percent ?? 0}%</dd><dt>Agent</dt><dd>{s.version}</dd></dl></article><article className="panel"><h2>Capture</h2><dl><dt>Received</dt><dd>{s.received_packets ?? 0}</dd><dt>Dropped</dt><dd>{s.dropped_packets ?? 0}</dd><dt>Heartbeat</dt><dd>{fmt(s.last_heartbeat ?? s.last_heartbeat_at)}</dd></dl>{s.last_error && <p role="alert">{s.last_error}</p>}</article></section>{desired && <ExternalSensorConfiguration sensor={configured} sensorId={id!} reload={() => q.refetch()} />}</>; }}</AsyncState>;
}

const newSource = (): CaptureSource => ({ interface: '', direction: 'INBOUND', bpf_filter: '', enabled: true });
const directions = ['INBOUND', 'OUTBOUND', 'BIDIRECTIONAL', 'UNKNOWN'];

function SourceRows({ sources, setSources, prefix = '' }: { sources: CaptureSource[]; setSources: (value: CaptureSource[]) => void; prefix?: string }) {
  const update = (index: number, changes: Partial<CaptureSource>) => setSources(sources.map((source, i) => i === index ? { ...source, ...changes } : source));
  return <div className="source-list">{sources.map((source, index) => { const number = index + 1; const interfaceLabel = prefix ? `${prefix} interface name ${number}` : `Interface name ${number}`; const directionLabel = prefix ? `${prefix} direction ${number}` : `Direction ${number}`; const bpfLabel = prefix ? `${prefix} BPF filter ${number}` : `BPF filter ${number}`; const enabledLabel = prefix ? `${prefix} enabled ${number}` : `Enabled ${number}`; return <fieldset className="source-row" key={index}><legend>{prefix || 'Interface'} {number}</legend><label>{interfaceLabel}<input value={source.interface} onChange={e => update(index, { interface: e.target.value })} required /></label><label>{directionLabel}<select value={source.direction} onChange={e => update(index, { direction: e.target.value })}>{directions.map(direction => <option key={direction}>{direction}</option>)}</select></label><label>{bpfLabel}<input value={source.bpf_filter} onChange={e => update(index, { bpf_filter: e.target.value })} /></label><label className="check"><input type="checkbox" checked={source.enabled} onChange={e => update(index, { enabled: e.target.checked })}/>{enabledLabel}</label>{sources.length > 1 && <button type="button" className="danger" aria-label={`Remove ${prefix ? `${prefix.toLowerCase()} ` : ''}interface ${number}`} onClick={() => setSources(sources.filter((_, i) => i !== index))}>Remove</button>}</fieldset>; })}</div>;
}

function CidrRows({ networks, setNetworks, prefix = '' }: { networks: string[]; setNetworks: (value: string[]) => void; prefix?: string }) {
  return <div className="cidr-list">{networks.map((network, index) => <div className="form-inline" key={index}><label>{`${prefix ? `${prefix} ` : ''}Internal CIDR ${index + 1}`}<input value={network} onChange={e => setNetworks(networks.map((value, i) => i === index ? e.target.value : value))} required /></label>{networks.length > 1 && <button type="button" className="danger" aria-label={`Remove internal network ${index + 1}`} onClick={() => setNetworks(networks.filter((_, i) => i !== index))}>Remove</button>}</div>)}</div>;
}

function ExternalSensors() {
  const query = useQuery<List<Enrollment>, Error>({ queryKey: ['sensor-enrollments'], queryFn: () => api.get('/sensor-enrollments') });
  return <><header><p className="eyebrow">EXTERNAL FLEET</p><h1>External sensors</h1><Link className="button-link" to="/external-sensors/enroll">Enroll sensor</Link></header><AsyncState query={query}>{data => items(data).length === 0 ? <div className="state">No external sensor enrollments</div> : <div className="table-wrap"><table aria-label="External sensor enrollments"><thead><tr><th>Name</th><th>Status</th><th>Expires</th><th>Sensor</th></tr></thead><tbody>{items(data).map(enrollment => { const enrollmentId = enrollment.enrollment_id ?? enrollment.id; return <tr key={enrollmentId}><td>{enrollment.name}<small>{enrollmentId}</small></td><td><span className={`badge ${enrollment.status.toLowerCase()}`}>{enrollment.status}</span></td><td>{fmt(enrollment.expires_at)}</td><td>{enrollment.sensor_id ? <Link to={`/sensors/${enrollment.sensor_id}`}>{enrollment.sensor_id}</Link> : 'Not claimed'}</td></tr>; })}</tbody></table></div>}</AsyncState></>;
}

function EnrollSensor() {
  const [sources, setSources] = useState<CaptureSource[]>([newSource()]);
  const [networks, setNetworks] = useState(['10.0.0.0/8']);
  const [secret, setSecret] = useState<EnrollmentSecret>();
  const [dismissed, setDismissed] = useState(false);
  const mutation = useMutation({ mutationFn: (body: unknown) => api.post<EnrollmentSecret>('/sensor-enrollments', body), onSuccess: result => { setSecret(result); setDismissed(false); } });
  const submit = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); const form = new FormData(event.currentTarget); mutation.mutate({ name: form.get('name'), expires_in_seconds: Number(form.get('expires')), capture_sources: sources, internal_networks: networks.map(value => value.trim()).filter(Boolean) }); };
  const copy = (text: string) => navigator.clipboard?.writeText(text);
  if (secret && !dismissed) return <section className="panel secret" aria-labelledby="enrollment-created"><h1 id="enrollment-created">Enrollment created</h1><p className="warning" role="alert">These credentials are shown only once. Store them securely before leaving this page.</p><label>One-time enrollment token<code className="secret-value">{secret.enrollment_token}</code></label><button type="button" onClick={() => copy(secret.enrollment_token)}>Copy enrollment token</button><label>Install command<code className="secret-value">{secret.install_command}</code></label><button type="button" onClick={() => copy(secret.install_command)}>Copy install command</button><p>Expires {fmt(secret.expires_at)}</p><button type="button" className="secondary" onClick={() => setDismissed(true)}>I have stored these credentials</button></section>;
  if (secret && dismissed) return <section className="panel"><h1>Enrollment secured</h1><p>The token and install command cannot be shown again.</p><Link to="/external-sensors">Return to enrollments</Link></section>;
  return <><header><p className="eyebrow">EXTERNAL FLEET</p><h1>Enroll sensor</h1></header><form className="panel form" onSubmit={submit}><div className="grid"><label>Sensor name<input name="name" required /></label><label>Enrollment lifetime (seconds)<input name="expires" type="number" min="60" defaultValue="3600" required /></label></div><h2>Capture interfaces</h2><SourceRows sources={sources} setSources={setSources}/><button type="button" className="secondary" onClick={() => setSources([...sources, newSource()])}>Add interface</button><h2>Internal networks</h2><CidrRows networks={networks} setNetworks={setNetworks}/><button type="button" className="secondary" onClick={() => setNetworks([...networks, ''])}>Add internal network</button>{mutation.error && <p role="alert">{mutation.error.message}</p>}<button disabled={mutation.isPending}>{mutation.isPending ? 'Creating…' : 'Create enrollment'}</button></form></>;
}

function Confirmation({ action, close, confirm, pending }: { action: 'Rotate' | 'Revoke'; close: () => void; confirm: () => void; pending: boolean }) {
  return <div className="dialog-backdrop"><section role="dialog" aria-modal="true" aria-labelledby={`${action}-credential-title`} className="panel dialog"><h2 id={`${action}-credential-title`}>{action} sensor credential</h2><p>{action === 'Rotate' ? 'The current credential will stop working after rotation.' : 'This sensor will no longer be able to authenticate.'}</p><div className="actions"><button className={action === 'Revoke' ? 'danger' : ''} disabled={pending} onClick={confirm}>Confirm {action.toLowerCase()}</button><button className="secondary" onClick={close}>Cancel</button></div></section></div>;
}

function ExternalSensorConfiguration({ sensor, sensorId, reload }: { sensor: Sensor; sensorId: string; reload: () => void }) {
  const desired = sensor.desired_configuration!;
  const observed = sensor.observed_configuration;
  const [sources, setSources] = useState(desired.capture_sources.map(source => ({ ...source, interface: source.interface ?? source.name ?? '' })));
  const [networks, setNetworks] = useState([...desired.internal_networks]);
  const [confirming, setConfirming] = useState<'Rotate' | 'Revoke'>();
  const save = useMutation({ mutationFn: () => api.put(`/sensors/${sensorId}/configuration`, { config_version: sensor.config_version ?? sensor.configuration_version ?? desired.version, capture_sources: sources, internal_networks: networks }), onSuccess: reload });
  const credential = useMutation({ mutationFn: (action: 'rotate' | 'revoke') => api.post(action === 'rotate' ? `/sensors/${sensorId}/credentials/rotate` : `/sensors/${sensorId}/revoke`), onSuccess: () => setConfirming(undefined) });
  const conflict = save.error && 'status' in save.error && save.error.status === 409;
  return <><section className="panel form"><h2>Desired configuration</h2><p className="muted">Configuration version {sensor.configuration_version ?? desired.version ?? 'unknown'}</p><SourceRows prefix="Desired" sources={sources} setSources={setSources}/><button type="button" className="secondary" onClick={() => setSources([...sources, newSource()])}>Add desired interface</button><CidrRows prefix="Desired" networks={networks} setNetworks={setNetworks}/><button type="button" className="secondary" onClick={() => setNetworks([...networks, ''])}>Add desired internal network</button>{save.error && <div role="alert" className="error-text"><strong>{conflict ? 'Configuration conflict' : 'Unable to save configuration'}</strong><p>{save.error.message}</p>{conflict && <button type="button" onClick={reload}>Reload latest configuration</button>}</div>}<button type="button" disabled={save.isPending} onClick={() => save.mutate()}>{save.isPending ? 'Saving…' : 'Save configuration'}</button></section><section className="panel"><h2>Observed configuration</h2><p>Agent version {observed?.version ?? 'not reported'}</p>{observed?.capture_sources?.length ? <div className="table-wrap"><table aria-label="Observed interface status"><thead><tr><th>Interface</th><th>Direction / filter</th><th>Status</th><th>Counters</th><th>Error</th></tr></thead><tbody>{observed.capture_sources.map((source, index) => <tr key={`${source.interface}-${index}`}><td>{source.interface ?? source.name}</td><td><code>{source.direction}</code> · {source.bpf_filter || 'No filter'}</td><td><span className={`badge ${(source.status ?? 'UNKNOWN').toLowerCase()}`}>{source.status ?? 'UNKNOWN'}</span></td><td>{source.received_packets ?? 0} received / {source.dropped_packets ?? 0} dropped</td><td>{source.last_error ? <span role="alert">{source.last_error}</span> : 'None'}</td></tr>)}</tbody></table></div> : <div className="state">No observed interface configuration</div>}</section><section className="panel danger-zone"><h2>Sensor credentials</h2><p>Rotating replaces the credential; revoking disconnects the sensor.</p><div className="actions"><button type="button" className="secondary" onClick={() => setConfirming('Rotate')}>Rotate credential</button><button type="button" className="danger" onClick={() => setConfirming('Revoke')}>Revoke credential</button></div>{credential.error && <p role="alert">{credential.error.message}</p>}</section>{confirming && <Confirmation action={confirming} pending={credential.isPending} close={() => setConfirming(undefined)} confirm={() => credential.mutate(confirming.toLowerCase() as 'rotate' | 'revoke')}/>}</>;
}

function AnalysisHistory() {
  const client = useQueryClient();
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const [source, setSource] = useState('');
  const [editing, setEditing] = useState<{ job: Job; name: string; description: string }>();
  const [deleting, setDeleting] = useState<Job>();
  const parameters = new URLSearchParams({ page_size: '200', sort: '-created_at' });
  if (search.trim()) parameters.set('search', search.trim());
  if (status) parameters.set('status', status);
  if (source) parameters.set('source_type', source);
  const query = useQuery<List<Job>, Error>({
    queryKey: ['analysis-history', search, status, source],
    queryFn: () => api.get(`/analysis-jobs?${parameters.toString()}`),
  });
  const update = useMutation<Job, Error, { id: string; name: string; description: string }>({
    mutationFn: value => api.patch(`/analysis-jobs/${value.id}`, { name: value.name, description: value.description }),
    onSuccess: () => { setEditing(undefined); client.invalidateQueries({ queryKey: ['analysis-history'] }); },
  });
  const remove = useMutation<void, Error, string>({
    mutationFn: id => api.delete<void>(`/analysis-jobs/${id}`),
    onSuccess: () => { setDeleting(undefined); client.invalidateQueries({ queryKey: ['analysis-history'] }); },
  });
  const submitEdit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (editing) update.mutate({ id: editing.job.id, name: editing.name, description: editing.description });
  };
  return <><header className="header-actions"><div><p className="eyebrow">INVESTIGATION ARCHIVE</p><h1>Analysis history</h1><p className="muted">Review, rename, annotate, or remove completed investigations. Captured evidence and detector settings remain immutable.</p></div><div className="actions"><Link className="button-link secondary-link" to="/analyses/upload">Upload PCAP</Link><Link className="button-link" to="/analyses/new">New analysis</Link></div></header><section className="panel history-filters"><label>Search<input value={search} onChange={event => setSearch(event.target.value)} placeholder="Name or analyst note" /></label><label>Status<select value={status} onChange={event => setStatus(event.target.value)}><option value="">All statuses</option>{['CREATED','WAITING_FOR_SENSOR','CAPTURING','UPLOADING','INGESTING','ANALYZING','COMPLETED','PARTIALLY_COMPLETED','FAILED','CANCELLED'].map(value => <option key={value}>{value}</option>)}</select></label><label>Source<select value={source} onChange={event => setSource(event.target.value)}><option value="">All sources</option><option value="SENSOR_CAPTURE">Sensor capture</option><option value="PCAP_UPLOAD">PCAP upload</option></select></label></section><AsyncState query={query} empty={data => items(data).length === 0}>{data => <div className="table-wrap"><table aria-label="Analysis history"><thead><tr><th>Analysis</th><th>Source</th><th>Status</th><th>Observed range</th><th>Created</th><th>Results</th><th>Manage</th></tr></thead><tbody>{items(data).map(job => <tr key={job.id}><td><Link to={`/analyses/${job.id}`}>{job.name}</Link><small>{job.description || job.id}</small></td><td>{job.source_type === 'PCAP_UPLOAD' ? <><strong>PCAP upload</strong><small>{job.source?.filename} · {formatBytes(job.source?.size_bytes)}</small></> : <><strong>{job.mode === 'HISTORICAL' ? 'Historical sensors' : 'Live sensors'}</strong><small>{job.sensor_ids?.length ?? 0} sensor(s)</small></>}</td><td><span className={`badge ${job.status.toLowerCase()}`}>{job.status}</span></td><td>{fmt(job.start_time)}<small>to {fmt(job.end_time)}</small></td><td>{fmt(job.created_at)}</td><td><strong>{job.candidate_count ?? 0}</strong> candidates<small>{job.packet_count ?? 0} packets · {job.flow_count ?? 0} flows</small></td><td><div className="row-actions"><button type="button" className="secondary" aria-label={`Edit ${job.name}`} onClick={() => setEditing({ job, name: job.name, description: job.description ?? '' })}>Edit</button><button type="button" className="danger" aria-label={`Delete ${job.name}`} disabled={!terminalStatuses.has(job.status)} title={terminalStatuses.has(job.status) ? 'Delete analysis' : 'Only terminal analyses can be deleted'} onClick={() => setDeleting(job)}>Delete</button></div></td></tr>)}</tbody></table></div>}</AsyncState>{editing && <div className="dialog-backdrop"><form className="panel dialog form" role="dialog" aria-modal="true" aria-labelledby="edit-analysis-title" onSubmit={submitEdit}><h2 id="edit-analysis-title">Edit analysis metadata</h2><p className="muted">Results, source packets, time range, and detector settings cannot be changed. Create a reanalysis to change detection parameters.</p><label>Analysis name<input value={editing.name} maxLength={200} onChange={event => setEditing({ ...editing, name: event.target.value })} required /></label><label>Analyst note<textarea value={editing.description} maxLength={5000} rows={5} onChange={event => setEditing({ ...editing, description: event.target.value })} /></label>{update.error && <p role="alert" className="error-text">{update.error.message}</p>}<div className="actions"><button disabled={update.isPending}>{update.isPending ? 'Saving…' : 'Save changes'}</button><button type="button" className="secondary" onClick={() => setEditing(undefined)}>Cancel</button></div></form></div>}{deleting && <div className="dialog-backdrop"><section className="panel dialog" role="dialog" aria-modal="true" aria-labelledby="delete-analysis-title"><h2 id="delete-analysis-title">Delete analysis</h2><p>Delete <strong>{deleting.name}</strong>, its candidates, and generated PCAP exports? This action cannot be undone.</p>{remove.error && <p role="alert" className="error-text">{remove.error.message}</p>}<div className="actions"><button type="button" className="danger" disabled={remove.isPending} onClick={() => remove.mutate(deleting.id)}>{remove.isPending ? 'Deleting…' : 'Delete permanently'}</button><button type="button" className="secondary" onClick={() => setDeleting(undefined)}>Cancel</button></div></section></div>}</>;
}

function PcapUpload() {
  const navigate = useNavigate();
  const [file, setFile] = useState<File>();
  const [validationError, setValidationError] = useState('');
  const [detectorWeights, setDetectorWeights] = useState<DetectorWeights>({ ...defaultDetectorWeights });
  const mutation = useMutation<Job, Error, { file: File; query: URLSearchParams }>({
    mutationFn: ({ file: selected, query }) => {
      const type = selected.name.toLowerCase().endsWith('.pcapng') ? 'application/x-pcapng' : 'application/vnd.tcpdump.pcap';
      return api.upload(`/pcap-analysis-jobs?${query.toString()}`, selected, type);
    },
    onSuccess: job => navigate(`/analyses/${job.id}`),
  });
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setValidationError('');
    if (!file) { setValidationError('Select a PCAP or PCAPNG file.'); return; }
    if (file.size > PCAP_UPLOAD_MAX_BYTES) { setValidationError('PCAP files must be 500 MiB or smaller.'); return; }
    const form = new FormData(event.currentTarget);
    const query = new URLSearchParams({
      name: String(form.get('name')),
      description: String(form.get('description') ?? ''),
      filename: file.name,
      internal_networks: String(form.get('internal_networks')),
      minimum_candidate_score: String(form.get('score')),
      minimum_distinct_clients: String(form.get('hosts')),
      periodicity_min_samples: String(form.get('samples')),
      ml_anomaly_enabled: String(form.get('ml_anomaly_enabled') === 'on'),
      ml_anomaly_allow_standalone: String(form.get('ml_anomaly_allow_standalone') === 'on'),
      idempotency_key: idempotencyKey(),
    });
    if (form.has('detector_weights_explicit')) query.set('detector_weights', JSON.stringify(detectorWeights));
    mutation.mutate({ file, query });
  };
  return <><header className="header-actions"><div><p className="eyebrow">OFFLINE INVESTIGATION</p><h1>Upload PCAP</h1><p className="muted">Analyze an existing capture with the same C2 correlation and scoring pipeline used for sensor traffic.</p></div><Link to="/analyses">View analysis history</Link></header><form className="panel form" onSubmit={submit}><label>Analysis name<input name="name" required maxLength={200} /></label><label>Analyst note<textarea name="description" rows={3} maxLength={5000} placeholder="Case, ticket, or collection context" /></label><label>Capture file<input name="pcap" type="file" accept=".pcap,.pcapng,.cap,application/vnd.tcpdump.pcap,application/octet-stream" onChange={event => { const selected = event.currentTarget.files?.[0]; mutation.reset(); setValidationError(''); if (selected && selected.size > PCAP_UPLOAD_MAX_BYTES) { event.currentTarget.value = ''; setFile(undefined); setValidationError('PCAP files must be 500 MiB or smaller.'); return; } setFile(selected); }} required /></label>{file && <div className="file-summary" role="status"><strong>{file.name}</strong><span>{formatBytes(file.size)}</span></div>}<div className="grid"><label>Internal networks<input name="internal_networks" defaultValue="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16" required /></label><label>Minimum score<input name="score" type="number" min="0" max="100" defaultValue="0" required /></label><label>Minimum internal hosts<input name="hosts" type="number" min="2" defaultValue="3" required /></label><label>Beacon minimum samples<input name="samples" type="number" min="3" defaultValue="5" required /></label></div><DetectorWeightFields weights={detectorWeights} setWeights={setDetectorWeights}/><fieldset><legend>모집단 이상 탐지</legend><label className="check"><input type="checkbox" name="ml_anomaly_enabled"/>후보군 대비 이상 통신 탐지 사용</label><label className="check"><input type="checkbox" name="ml_anomaly_allow_standalone"/>이상 탐지만으로 후보 생성 허용</label><p className="muted">기본값은 사용 안 함입니다. 단독 후보 생성은 실험 기능이며, 허용하지 않으면 다른 탐지 근거가 있는 후보의 점수만 보강합니다.</p></fieldset><p className="muted">Supported containers: classic PCAP and PCAPNG. Supported packet links include Ethernet, raw IP, Linux cooked capture v1/v2, and loopback. The upload limit is 500 MiB and 2,000,000 packets.</p>{(validationError || mutation.error) && <p role="alert" className="error-text">{validationError || mutation.error?.message}</p>}<button disabled={mutation.isPending}>{mutation.isPending ? 'Uploading and analyzing…' : 'Upload and analyze'}</button></form></>;
}

function NewAnalysis() {
  const navigate = useNavigate();
  const [detectorWeights, setDetectorWeights] = useState<DetectorWeights>({ ...defaultDetectorWeights });
  const sensors = useQuery<List<Sensor>, Error>({ queryKey: ['sensors'], queryFn: () => api.get('/sensors') });
  const mutation = useMutation({ mutationFn: (body: unknown) => api.post<Job>('/analysis-jobs', body), onSuccess: job => navigate(`/analyses/${job.id}`) });
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const start = new Date();
    const end = new Date(start.getTime() + Number(form.get('duration')) * 1000);
    mutation.mutate({
      name: form.get('name'),
      idempotency_key: idempotencyKey(),
      sensor_ids: form.getAll('sensor_ids'),
      mode: form.get('mode'),
      start_time: start.toISOString(),
      end_time: end.toISOString(),
      internal_networks: String(form.get('internal_networks')).split(',').map(value => value.trim()).filter(Boolean),
      capture: { duration_seconds: Number(form.get('duration')), max_packets: Number(form.get('max_packets')), directions: form.getAll('directions'), bpf_filter: form.get('bpf'), store_pcap: form.get('store_pcap') === 'on' },
      analysis: { profile: 'ddos_botnet', minimum_candidate_score: Number(form.get('score')), minimum_distinct_clients: Number(form.get('hosts')), ...(form.has('detector_weights_explicit') ? { detector_weights: detectorWeights } : {}), ml_anomaly_enabled: form.get('ml_anomaly_enabled') === 'on', ml_anomaly_allow_standalone: form.get('ml_anomaly_allow_standalone') === 'on' },
    });
  };
  return <><header><p className="eyebrow">INVESTIGATION</p><h1>New analysis</h1></header><form className="panel form" onSubmit={submit}><label>Analysis name<input name="name" required /></label><fieldset><legend>Sensors</legend><AsyncState query={sensors}>{data => <>{items(data).map(sensor => <label className="check" key={sensor.sensor_id}><input type="checkbox" name="sensor_ids" value={sensor.sensor_id} aria-label={sensor.name}/>{sensor.name}</label>)}</>}</AsyncState></fieldset><div className="grid"><label>Data source<select name="mode"><option value="LIVE">Live capture</option><option value="HISTORICAL">Historical</option></select></label><label>Duration (seconds)<input name="duration" type="number" min="1" defaultValue="300" /></label><label>Internal networks<input name="internal_networks" defaultValue="10.0.0.0/8" required /></label><label>Maximum packets<input name="max_packets" type="number" min="1" defaultValue="2000000" /></label><label>BPF filter<input name="bpf" defaultValue="ip" /></label><label>Minimum score<input name="score" type="number" min="0" max="100" defaultValue="20" /></label><label>Minimum internal hosts<input name="hosts" type="number" min="2" defaultValue="3" /></label></div><fieldset><legend>Directions</legend>{['INBOUND','OUTBOUND'].map(value => <label className="check" key={value}><input type="checkbox" name="directions" value={value} defaultChecked/>{value}</label>)}</fieldset><DetectorWeightFields weights={detectorWeights} setWeights={setDetectorWeights}/><fieldset><legend>모집단 이상 탐지</legend><label className="check"><input type="checkbox" name="ml_anomaly_enabled"/>후보군 대비 이상 통신 탐지 사용</label><label className="check"><input type="checkbox" name="ml_anomaly_allow_standalone"/>이상 탐지만으로 후보 생성 허용</label><p className="muted">기본값은 사용 안 함입니다. 단독 후보 생성은 실험 기능이며, 허용하지 않으면 다른 탐지 근거가 있는 후보의 점수만 보강합니다.</p></fieldset><label className="check"><input type="checkbox" name="store_pcap" defaultChecked/>Store PCAP</label>{mutation.error && <p role="alert">{mutation.error.message}</p>}<button disabled={mutation.isPending}>{mutation.isPending ? 'Starting…' : 'Start analysis'}</button></form></>;
}

function JobReanalysis({ job }: { job: Job }) {
  const navigate = useNavigate();
  const recorded = job.analysis?.detector_weights;
  const initialWeights = detectorDefinitions.reduce<DetectorWeights>((result, [name]) => {
    const value = recorded && typeof recorded === 'object' ? (recorded as Record<string, unknown>)[name] : undefined;
    result[name] = typeof value === 'number' && value >= 0 && value <= 2 ? value : 1;
    return result;
  }, {});
  const [weights, setWeights] = useState<DetectorWeights>(initialWeights);
  const reanalyze = useMutation({
    mutationFn: () => api.post<Job>(`/analysis-jobs/${job.id}/reanalyze`, { idempotency_key: idempotencyKey(), detector_weights: weights }),
    onSuccess: created => navigate(`/analyses/${created.id}`),
  });
  return <section className="panel compact"><h2>가중치 조정 후 재분석</h2><p className="muted">데이터셋 {job.dataset_id}을 다시 업로드하거나 파싱하지 않고 탐지 가중치별 후보 점수를 비교합니다.</p><DetectorWeightFields weights={weights} setWeights={setWeights} applyDefault={false}/>{reanalyze.error && <p role="alert" className="error-text">{reanalyze.error.message}</p>}<button disabled={reanalyze.isPending} onClick={() => reanalyze.mutate()}>{reanalyze.isPending ? '재분석 생성 중…' : '탐지 가중치로 재분석'}</button></section>;
}

function JobDetail() {
  const { id } = useParams();
  const [notice, setNotice] = useState('');
  const q = useQuery<Job, Error>({
    queryKey: ['job', id],
    queryFn: () => api.get(`/analysis-jobs/${id}`),
    refetchInterval: query => terminalStatuses.has(query.state.data?.status ?? '') ? false : 3000,
  });
  const candidates = useQuery<List<Candidate>, Error>({
    queryKey: ['job-candidates', id],
    queryFn: () => api.get(`/analysis-jobs/${id}/candidates?page_size=200`),
    refetchInterval: () => terminalStatuses.has(q.data?.status ?? '') ? false : 3000,
  });
  const cancel = useMutation({ mutationFn: () => api.post(`/analysis-jobs/${id}/cancel`, { reason: 'operator requested from web console' }), onSuccess: () => { setNotice('Cancellation requested'); q.refetch(); } });
  return <AsyncState query={q}>{j => {
    const terminal = terminalStatuses.has(j.status);
    const source = j.source;
    return <>
      <header className="header-actions"><div><p className="eyebrow">ANALYSIS DETAIL</p><h1>{j.name}</h1><span className={`badge ${j.status.toLowerCase()}`}>{j.status}</span><p className="record-id">Job {j.id}{j.dataset_id ? ` · Dataset ${j.dataset_id}` : ''}</p></div><Link to="/analyses">Back to analysis history</Link></header>
      {j.description && <section className="panel"><h2>Analyst note</h2><p>{j.description}</p></section>}
      <section className="panel">
        <label>Progress <progress value={terminal ? 100 : j.progress_percent ?? 0} max="100">{terminal ? 100 : j.progress_percent}%</progress></label>
        <section className="metrics compact"><article><strong>{(j.packet_count ?? 0).toLocaleString()}</strong><span>Packets</span></article><article><strong>{(j.flow_count ?? 0).toLocaleString()}</strong><span>Flows</span></article><article><strong>{(j.candidate_count ?? 0).toLocaleString()}</strong><span>Candidates</span></article><article><strong>{strings(j.sensor_ids).length}</strong><span>Sensors</span></article></section>
        {strings(j.warnings).map(warning => <p className="warning" key={warning}>{warning}</p>)}
        {!terminal && <button className="danger" disabled={cancel.isPending} onClick={() => cancel.mutate()}>{cancel.isPending ? 'Cancelling…' : 'Cancel analysis'}</button>}
        {cancel.error && <p role="alert" className="error-text">{cancel.error.message}</p>}{notice && <p role="status">{notice}</p>}
      </section>
      <section className="grid compact">
        <article className="panel"><h2>Source and parsing</h2><dl><dt>Type</dt><dd>{j.source_type === 'PCAP_UPLOAD' ? 'PCAP upload' : j.mode ?? 'Sensor capture'}</dd><dt>File</dt><dd>{source?.filename ?? 'Sensor dataset'}</dd><dt>Format</dt><dd>{source?.capture_format ?? 'Not reported'}</dd><dt>Size</dt><dd>{formatBytes(source?.size_bytes)}</dd><dt>Captured packets</dt><dd>{formatValue(source?.captured_packet_count)}</dd><dt>Parsed packets</dt><dd>{formatValue(source?.parsed_packet_count)}</dd><dt>Skipped packets</dt><dd>{formatValue(source?.skipped_packet_count)}</dd><dt>Link types</dt><dd>{formatValue(source?.link_types)}</dd><dt>SHA-256</dt><dd className="hash-value">{source?.sha256 ?? 'Not applicable'}</dd></dl></article>
        <article className="panel"><h2>Observation timeline</h2><dl><dt>Observed from</dt><dd>{fmt(j.start_time)}</dd><dt>Observed to</dt><dd>{fmt(j.end_time)}</dd><dt>Created</dt><dd>{fmt(j.created_at)}</dd><dt>Updated</dt><dd>{fmt(j.updated_at)}</dd><dt>Completed</dt><dd>{fmt(j.completed_at)}</dd><dt>Parent analysis</dt><dd>{j.parent_job_id ? <Link to={`/analyses/${j.parent_job_id}`}>{j.parent_job_id}</Link> : 'None'}</dd></dl></article>
      </section>
      <section className="grid compact">
        <article className="panel"><h2>Analysis scope</h2><dl><dt>Internal networks</dt><dd>{formatValue(j.internal_networks)}</dd><dt>Sensors</dt><dd>{formatValue(j.sensor_ids)}</dd>{Object.entries(j.capture ?? {}).map(([key, value]) => <Fragment key={key}><dt>{humanize(key)}</dt><dd>{formatValue(value)}</dd></Fragment>)}</dl></article>
        <article className="panel detector-settings"><h2>탐지 설정</h2>{Object.keys(j.analysis ?? {}).length ? <dl>{Object.entries(j.analysis ?? {}).map(([key, value]) => <Fragment key={key}><dt title={key}>{fieldLabel(key)}</dt><dd>{formatValue(value)}</dd></Fragment>)}</dl> : <p className="muted">기록된 탐지 설정이 없습니다.</p>}</article>
      </section>
      {j.status === 'COMPLETED' && j.dataset_id && <JobReanalysis key={j.id} job={j}/>}
      <section className="panel compact"><h2>탐지 후보</h2><AsyncState query={candidates} empty={data => items(data).length === 0}>{data => <div className="table-wrap"><table aria-label="Analysis candidates"><thead><tr><th>후보</th><th>점수</th><th>호스트 / 센서</th><th>네트워크 정보</th><th>탐지 근거</th><th>관측 시각</th></tr></thead><tbody>{items(data).map(candidate => { const hosts = candidateHosts(candidate); const sensors = candidateSensors(candidate); const protocols = strings(candidate.protocols); const ports = numbers(candidate.ports); const evidence = candidateEvidence(candidate); return <tr key={candidate.id}><td><Link to={`/candidates/${candidate.id}`}>{candidate.candidate_ip}</Link><small className={candidate.severity.toLowerCase()}>{candidate.severity}</small></td><td><strong>{candidate.score}</strong></td><td>{hosts.length || candidate.distinct_internal_hosts || 0}개 호스트<small>{sensors.length}개 센서</small></td><td>{protocols.length ? protocols.join(', ') : '알 수 없는 프로토콜'}<small>{ports.length ? `포트 ${ports.join(', ')}` : '서비스 포트 없음'}</small></td><td>{candidate.evidence_count ?? evidence.length}건<small>{evidence.map(item => evidenceLabel(item.type)).join(', ') || '상세 근거 없음'}</small></td><td>{fmt(candidate.first_seen)}<small>~ {fmt(candidate.last_seen)}</small></td></tr>; })}</tbody></table></div>}</AsyncState></section>
      <JobFlowReviewPanel jobId={j.id} />
      <section className="panel compact"><h2>State transitions</h2>{j.transitions?.length ? <ol className="timeline">{j.transitions.map((transition, index) => <li key={`${transition.to_status}-${transition.occurred_at}-${index}`}><strong>{transition.to_status}</strong><span>{fmt(transition.occurred_at)}</span><p>{transition.reason ?? 'No transition reason recorded'}{transition.from_status ? ` · from ${transition.from_status}` : ''}</p></li>)}</ol> : <p className="muted">No state transition history was recorded.</p>}</section>
    </>;
  }}</AsyncState>;
}

type CandidateFilters = { severity: string; minimumScore: string; includeSuppressed: boolean; sort: string };
const defaultCandidateFilters: CandidateFilters = { severity: '', minimumScore: '0', includeSuppressed: false, sort: '-score' };

function Candidates() {
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState(defaultCandidateFilters);
  const [draft, setDraft] = useState(defaultCandidateFilters);
  const q = useQuery<Page<Candidate>, Error>({
    queryKey: ['candidates', page, filters],
    queryFn: () => {
      const parameters = new URLSearchParams({ page: String(page), page_size: '50', minimum_score: filters.minimumScore || '0', sort: filters.sort });
      if (filters.severity) parameters.set('severity', filters.severity);
      if (filters.includeSuppressed) parameters.set('include_suppressed', 'true');
      return api.get(`/candidates?${parameters}`);
    },
  });
  const applyFilters = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); setPage(1); setFilters({ ...draft, minimumScore: draft.minimumScore || '0' }); };
  const resetFilters = () => { setDraft(defaultCandidateFilters); setFilters(defaultCandidateFilters); setPage(1); };
  return <><header><p className="eyebrow">DETECTION RESULTS</p><h1>Candidates</h1><p className="muted">Review scored destinations across every analysis. Filter on the Controller so large result sets remain complete and responsive.</p></header><form className="candidate-filters" onSubmit={applyFilters}><label>Severity<select value={draft.severity} onChange={event => setDraft({ ...draft, severity: event.target.value })}><option value="">Any</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></label><label>Minimum score<input type="number" min="0" max="100" value={draft.minimumScore} onChange={event => setDraft({ ...draft, minimumScore: event.target.value })} /></label><label>Sort candidates<select value={draft.sort} onChange={event => setDraft({ ...draft, sort: event.target.value })}><option value="-score">Score: high to low</option><option value="score">Score: low to high</option><option value="candidate_ip">IP address</option><option value="-last_seen">Most recently seen</option><option value="first_seen">First seen</option></select></label><label className="check"><input type="checkbox" checked={draft.includeSuppressed} onChange={event => setDraft({ ...draft, includeSuppressed: event.target.checked })} />Include suppressed candidates</label><button>Apply filters</button><button type="button" className="secondary" onClick={resetFilters}>Reset</button></form><AsyncState query={q} empty={data => items(data).length === 0}>{data => <><div className="table-wrap"><table aria-label="C2 candidates"><thead><tr><th>Candidate</th><th>Score</th><th>Hosts</th><th>Sensors</th><th>Protocol / port</th><th>Observed</th><th>Primary evidence</th></tr></thead><tbody>{items(data).map(candidate => { const hosts = candidateHosts(candidate); const sensors = candidateSensors(candidate); const protocols = strings(candidate.protocols); const ports = numbers(candidate.ports); const evidence = candidateEvidence(candidate); return <tr key={candidate.id}><td><Link to={`/candidates/${candidate.id}`}>{candidate.candidate_ip}</Link><small className={candidate.severity.toLowerCase()}>{candidate.severity}</small></td><td><strong>{candidate.score}</strong></td><td>{hosts.length || candidate.distinct_internal_hosts || 0}</td><td>{sensors.length}</td><td>{protocols.length ? protocols.join(', ') : 'Unknown'}<small>{ports.length ? `Ports ${ports.join(', ')}` : 'No ports reported'}</small></td><td>{fmt(candidate.first_seen)}<small>to {fmt(candidate.last_seen)}</small></td><td title={evidence[0]?.type}>{evidenceLabel(evidence[0]?.type)}<small>{evidence.length}건의 탐지 신호</small></td></tr>; })}</tbody></table></div><CandidatePagination data={data} page={page} onPage={setPage} /></>}</AsyncState></>;
}

function CandidatePagination({ data, page, onPage }: { data: Page<Candidate>; page: number; onPage: (page: number) => void }) {
  const pageSize = data.page_size ?? 50;
  const total = data.total ?? items(data).length;
  const current = data.page ?? page;
  const first = total === 0 ? 0 : (current - 1) * pageSize + 1;
  return <div className="pagination"><span>Candidates {first}–{Math.min(current * pageSize, total)} of {total}</span><div className="row-actions"><button type="button" className="secondary" disabled={current <= 1} onClick={() => onPage(Math.max(1, current - 1))}>Previous candidates</button><button type="button" className="secondary" disabled={current * pageSize >= total} onClick={() => onPage(current + 1)}>Next candidates</button></div></div>;
}

function CandidateDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [notice, setNotice] = useState('');
  const [confirmDelete, setConfirmDelete] = useState(false);
  const q = useQuery<Candidate, Error>({ queryKey: ['candidate', id], queryFn: () => api.get(`/candidates/${id}`) });
  const exportPcap = useMutation({ mutationFn: () => api.post('/pcap-exports', { job_id: q.data?.job_id, candidate_id: id }), onSuccess: () => setNotice('PCAP export requested') });
  const reanalyze = useMutation({ mutationFn: () => api.post(`/analysis-jobs/${q.data?.job_id}/reanalyze`, { idempotency_key: idempotencyKey() }), onSuccess: () => setNotice('Reanalysis created') });
  const addToAllowlist = useMutation({ 
    mutationFn: (body: unknown) => api.post('/allowlist', body), 
    onSuccess: () => setNotice('Added to allowlist') 
  });
  const deleteCandidate = useMutation({ 
    mutationFn: () => api.delete(`/candidates/${id}`), 
    onSuccess: () => {
      setConfirmDelete(false);
      navigate('/candidates');
    }
  });
  return <AsyncState query={q}>{candidate => {
    const hosts = candidateHosts(candidate);
    const sensors = candidateSensors(candidate);
    const protocols = strings(candidate.protocols);
    const ports = numbers(candidate.ports);
    const domains = strings(candidate.domains);
    const evidence = candidateEvidence(candidate);
    const adjustments = Array.isArray(candidate.adjustments) ? candidate.adjustments : [];
    const buckets = Array.isArray(candidate.traffic_buckets) ? candidate.traffic_buckets : [];
    const traffic = numbers(candidate.traffic_series).length ? numbers(candidate.traffic_series) : buckets.map(bucket => bucket.packets);
    return <>
      <header className="header-actions"><div><p className="eyebrow">CANDIDATE DETAIL</p><h1>{candidate.candidate_ip}</h1><span className={`badge ${candidate.severity.toLowerCase()}`}>{candidate.score} · {candidate.severity}</span><p className="record-id">Candidate {candidate.id}</p></div>{candidate.job_id && <Link to={`/analyses/${candidate.job_id}`}>View source analysis</Link>}</header>
      <section className="metrics compact"><article><strong>{hosts.length || candidate.distinct_internal_hosts || 0}</strong><span>내부 호스트</span></article><article><strong>{sensors.length}</strong><span>센서</span></article><article><strong>{(candidate.flow_count ?? 0).toLocaleString()}</strong><span>흐름</span></article><article><strong>{(candidate.packet_count ?? 0).toLocaleString()}</strong><span>패킷</span></article><article><strong>{formatBytes(candidate.byte_count)}</strong><span>통신량</span></article><article><strong>{evidence.length}</strong><span>탐지 신호</span></article></section>
      <div className="grid compact"><section className="panel"><h2>Traffic over time</h2>{traffic.length ? <MiniChart values={traffic} label="Traffic over time" /> : <p className="muted">No traffic series was retained for this candidate.</p>}{buckets.length > 0 && <div className="table-wrap"><table aria-label="Candidate traffic buckets"><thead><tr><th>Bucket start</th><th>Flows</th><th>Packets</th><th>Bytes</th></tr></thead><tbody>{buckets.map(bucket => <tr key={bucket.start}><td>{fmt(bucket.start)}</td><td>{bucket.flows}</td><td>{bucket.packets}</td><td>{formatBytes(bucket.bytes)}</td></tr>)}</tbody></table></div>}</section><section className="panel"><h2>Network context</h2><dl><dt>Protocols</dt><dd>{formatValue(protocols)}</dd><dt>Service ports</dt><dd>{formatValue(ports)}</dd><dt>Domains</dt><dd>{formatValue(domains)}</dd><dt>First observed</dt><dd>{fmt(candidate.first_seen)}</dd><dt>Last observed</dt><dd>{fmt(candidate.last_seen)}</dd><dt>Internal hosts</dt><dd>{formatValue(hosts)}</dd><dt>Sensors</dt><dd>{formatValue(sensors)}</dd><dt>Related attack targets</dt><dd>{formatValue(candidate.related_attack_targets)}</dd></dl></section></div>
      <FlowReviewPanel candidate={candidate} />
      <section className="panel compact detection-evidence"><h2>탐지 근거</h2>{evidence.length ? evidence.map((item, index) => <article className="evidence detailed" key={`${item.detector ?? item.type}-${index}`}><div className="evidence-heading"><strong title={item.type}>{evidenceLabel(item.type)}</strong><small title={item.detector}>{detectorLabel(item.detector)}{item.version ? ` · v${item.version}` : ''}</small></div><span className="evidence-score">+{formatValue(item.contribution ?? item.score ?? item.raw_score ?? 0)}</span><p>{item.description ?? '기록된 탐지 근거 설명이 없습니다.'}</p><dl><dt>원시 점수</dt><dd>{formatValue(item.raw_score)}</dd><dt>신뢰도</dt><dd>{item.confidence === undefined ? '기록 없음' : `${Math.round(item.confidence * 100)}%`}</dd><dt>관측 시각</dt><dd>{fmt(item.first_seen)} – {fmt(item.last_seen)}</dd><dt>호스트</dt><dd>{formatValue(item.hosts)}</dd><dt>센서</dt><dd>{formatValue(item.sensors)}</dd></dl>{item.metrics && Object.keys(item.metrics).length > 0 && <div className="evidence-metrics">{Object.entries(item.metrics).map(([key, value]) => <span key={key} title={key}><b>{metricLabel(key)}</b><output>{localizedMetricValue(value)}</output></span>)}</div>}{strings(item.warnings).map(warning => <p className="warning" key={warning}>{warning}</p>)}</article>) : <p className="muted">기록된 탐지 근거가 없습니다.</p>}</section>
      <section className="panel compact"><h2>점수 조정</h2>{adjustments.length ? <ul className="adjustments">{adjustments.map((adjustment, index) => <li key={`${adjustment.kind}-${index}`}><strong className={adjustment.points < 0 ? 'critical' : 'low'}>{adjustment.points > 0 ? '+' : ''}{adjustment.points}</strong><span title={String(adjustment.kind)}>{adjustmentLabel(adjustment.kind)} · {adjustment.explanation}</span></li>)}</ul> : <p className="muted">적용된 점수 조정이 없습니다.</p>}<div className="actions">
        <button disabled={!candidate.job_id || exportPcap.isPending} onClick={() => exportPcap.mutate()}>{exportPcap.isPending ? 'Requesting export…' : 'Export candidate PCAP'}</button>
        <button className="secondary" disabled={!candidate.job_id || reanalyze.isPending} onClick={() => reanalyze.mutate()}>{reanalyze.isPending ? 'Creating reanalysis…' : 'Reanalyze'}</button>
        <button className="secondary" disabled={addToAllowlist.isPending} onClick={() => addToAllowlist.mutate({value: candidate.candidate_ip, type: 'IP', description: `Added from candidate ${candidate.id}`})}>
          {addToAllowlist.isPending ? 'Adding to allowlist…' : 'Add to Allowlist'}
        </button>
        <button className="danger" disabled={deleteCandidate.isPending} onClick={() => setConfirmDelete(true)}>
          Delete candidate
        </button>
      </div>{(exportPcap.error || reanalyze.error || addToAllowlist.error || deleteCandidate.error) && <p role="alert" className="error-text">{[exportPcap.error?.message, reanalyze.error?.message, addToAllowlist.error?.message, deleteCandidate.error?.message].filter(Boolean).join(', ')}</p>}{notice && <p role="status">{notice}</p>}</section>
      {confirmDelete && <div className="dialog-backdrop"><section role="dialog" aria-modal="true" aria-labelledby="delete-candidate-title" className="panel dialog"><h2 id="delete-candidate-title">Delete candidate permanently</h2><p>This removes {candidate.candidate_ip} from the analysis results. This action cannot be undone.</p>{deleteCandidate.error && <p role="alert" className="error-text">{deleteCandidate.error.message}</p>}<div className="actions"><button className="danger" disabled={deleteCandidate.isPending} onClick={() => deleteCandidate.mutate()}>{deleteCandidate.isPending ? 'Deleting…' : 'Delete permanently'}</button><button type="button" className="secondary" disabled={deleteCandidate.isPending} onClick={() => { deleteCandidate.reset(); setConfirmDelete(false); }}>Cancel</button></div></section></div>}
    </>;
  }}</AsyncState>;
}

function JobFlowReviewPanel({ jobId }: { jobId: string }) {
  const defaults = { candidateIp: '', direction: '', protocol: '', port: '', sourcePort: '', destinationPort: '', payloadOnly: true, excludeMatches: false };
  const [draft, setDraft] = useState(defaults);
  const [filters, setFilters] = useState(defaults);
  const [page, setPage] = useState(1);
  const query = useQuery<Page<FlowRecordReview>, Error>({
    queryKey: ['job-flows', jobId, filters, page],
    queryFn: () => {
      const parameters = new URLSearchParams({ page: String(page), page_size: '50' });
      if (filters.candidateIp) parameters.set('candidate_ip', filters.candidateIp);
      if (filters.direction) parameters.set('direction', filters.direction);
      if (filters.protocol) parameters.set('protocol', filters.protocol);
      if (filters.port) parameters.set('port', filters.port);
      if (filters.sourcePort) parameters.set('source_port', filters.sourcePort);
      if (filters.destinationPort) parameters.set('destination_port', filters.destinationPort);
      if (filters.payloadOnly) parameters.set('has_payload', 'true');
      if (filters.excludeMatches) parameters.set('exclude_matches', 'true');
      return api.get(`/analysis-jobs/${jobId}/flows?${parameters.toString()}`);
    },
  });
  const applyFilters = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setPage(1);
    setFilters({ ...draft });
  };
  const resetFilters = () => {
    setDraft(defaults);
    setFilters(defaults);
    setPage(1);
  };
  return <section className="panel compact"><h2>All analysis flows</h2><p className="muted">Browse and label a flow even when no detector promoted its external IP to a candidate. Payload-bearing flows are shown by default. Exclusion mode removes flows that match every configured condition.</p><form className="flow-filters" onSubmit={applyFilters}><label>Endpoint IP or CIDR<input value={draft.candidateIp} onChange={event => setDraft({ ...draft, candidateIp: event.target.value })} placeholder="IP or CIDR, internal or external" /></label><label>Direction<select value={draft.direction} onChange={event => setDraft({ ...draft, direction: event.target.value })}><option value="">Any</option>{directions.map(direction => <option key={direction}>{direction}</option>)}</select></label><label>Protocol<input value={draft.protocol} onChange={event => setDraft({ ...draft, protocol: event.target.value })} placeholder="TCP or UDP" /></label><label>External service port<input value={draft.port} onChange={event => setDraft({ ...draft, port: event.target.value })} type="number" min="0" max="65535" /></label><label>Source port<input value={draft.sourcePort} onChange={event => setDraft({ ...draft, sourcePort: event.target.value })} type="number" min="0" max="65535" /></label><label>Destination port<input value={draft.destinationPort} onChange={event => setDraft({ ...draft, destinationPort: event.target.value })} type="number" min="0" max="65535" /></label><label className="check"><input type="checkbox" checked={draft.payloadOnly} onChange={event => setDraft({ ...draft, payloadOnly: event.target.checked })} />Payload only</label><label className="check"><input type="checkbox" checked={draft.excludeMatches} onChange={event => setDraft({ ...draft, excludeMatches: event.target.checked })} />Filter out matching flows</label><button>Apply filters</button><button type="button" className="secondary" onClick={resetFilters}>Reset</button></form><AsyncState query={query} empty={data => items(data).length === 0}>{data => <><div className="table-wrap"><table aria-label="Analysis flows"><thead><tr><th>Observed</th><th>Direction</th><th>Endpoints</th><th>Protocol</th><th>Volume</th><th>Payload features</th><th>Current label</th><th>Review</th></tr></thead><tbody>{items(data).map(flow => <FlowReviewRow key={flow.flow_id} flow={flow} />)}</tbody></table></div><FlowPagination data={data} page={page} onPage={setPage}/></>}</AsyncState></section>;
}

function FlowPagination({ data, page, onPage }: { data: Page<FlowRecordReview>; page: number; onPage: (page: number) => void }) {
  const pageSize = data.page_size ?? 50;
  const total = data.total ?? items(data).length;
  const current = data.page ?? page;
  return <div className="pagination"><span>Flows {(current - 1) * pageSize + 1}–{Math.min(current * pageSize, total)} of {total}</span><div className="row-actions"><button type="button" className="secondary" disabled={page <= 1} onClick={() => onPage(Math.max(1, page - 1))}>Previous flows</button><button type="button" className="secondary" disabled={page * pageSize >= total} onClick={() => onPage(page + 1)}>Next flows</button></div></div>;
}

function FlowReviewPanel({ candidate }: { candidate: Candidate }) {
  const [page, setPage] = useState(1);
  const query = useQuery<Page<FlowRecordReview>, Error>({
    queryKey: ['candidate-flows', candidate.job_id, candidate.candidate_ip, page],
    queryFn: () => api.get(`/analysis-jobs/${candidate.job_id}/flows?candidate_ip=${encodeURIComponent(candidate.candidate_ip)}&page=${page}&page_size=50`),
    enabled: Boolean(candidate.job_id),
  });
  if (!candidate.job_id) return <section className="panel compact"><h2>Flow review</h2><p className="muted">The source analysis is unavailable, so its flows cannot be reviewed.</p></section>;
  return <section className="panel compact"><h2>Flow review</h2><p className="muted">Inspect a retained payload only when needed, then record an analyst verdict. C2 labels can create a reusable, non-reversible payload signature for future analyses.</p><AsyncState query={query} empty={data => items(data).length === 0}>{data => <><div className="table-wrap"><table aria-label="Candidate flows"><thead><tr><th>Observed</th><th>Direction</th><th>Endpoints</th><th>Protocol</th><th>Volume</th><th>Payload features</th><th>Current label</th><th>Review</th></tr></thead><tbody>{items(data).map(flow => <FlowReviewRow key={flow.flow_id} flow={flow} candidateIp={candidate.candidate_ip} />)}</tbody></table></div><FlowPagination data={data} page={page} onPage={setPage} /></>}</AsyncState></section>;
}

function FlowReviewRow({ flow, candidateIp }: { flow: FlowRecordReview; candidateIp?: string }) {
  const client = useQueryClient();
  const navigate = useNavigate();
  const [verdict, setVerdict] = useState<'C2' | 'BENIGN'>();
  const [confidence, setConfidence] = useState<'CONFIRMED' | 'HIGH' | 'MEDIUM'>('HIGH');
  const [note, setNote] = useState('');
  const [createSignature, setCreateSignature] = useState(true);
  const [signatureName, setSignatureName] = useState('');
  const [notice, setNotice] = useState('');
  const preview = useMutation<PayloadPreview, Error>({
    mutationFn: () => api.get(`/analysis-jobs/${flow.job_id}/flows/${flow.flow_id}/payload-preview`),
  });
  const guidance = useMutation<DetectionGuidance, Error>({
    mutationFn: () => api.get(`/analysis-jobs/${flow.job_id}/flows/${flow.flow_id}/detection-guidance`),
  });
  const guidedReanalysis = useMutation<Job, Error>({
    mutationFn: () => api.post(`/analysis-jobs/${flow.job_id}/reanalyze`, {
      idempotency_key: idempotencyKey(),
      ...guidance.data?.recommended_reanalysis,
    }),
    onSuccess: created => navigate(`/analyses/${created.id}`),
  });
  const label = useMutation<{ label: FlowLabel; signature?: PayloadSignature | null }, Error>({
    mutationFn: () => api.post(`/analysis-jobs/${flow.job_id}/flow-labels`, {
      flow_id: flow.flow_id,
      verdict,
      confidence,
      note,
      create_signature: verdict === 'C2' && createSignature,
      signature_name: verdict === 'C2' && createSignature ? signatureName : undefined,
      signature_description: verdict === 'C2' && createSignature ? note : '',
    }),
    onSuccess: result => {
      setNotice(result.signature ? `C2 label and signature "${result.signature.name}" saved.` : `${result.label.verdict} label saved.`);
      if (result.label.verdict === 'C2') guidance.mutate();
      setVerdict(undefined);
      setNote('');
      client.invalidateQueries({ queryKey: ['candidate-flows'] });
      client.invalidateQueries({ queryKey: ['job-flows', flow.job_id] });
      client.invalidateQueries({ queryKey: ['payload-signatures'] });
    },
  });
  const startReview = (nextVerdict: 'C2' | 'BENIGN') => {
    label.reset();
    setNotice('');
    setVerdict(nextVerdict);
    setCreateSignature(nextVerdict === 'C2');
    if (nextVerdict === 'C2' && !signatureName) setSignatureName(`${flow.protocol} ${flow.external_ip ?? candidateIp ?? 'unknown'} payload`);
  };
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    label.mutate();
  };
  return <Fragment>
    <tr>
      <td>{fmt(flow.timestamp)}<small>{flow.sensor_id ?? 'Unknown sensor'}</small></td>
      <td><code>{flow.direction}</code></td>
      <td><code>{flow.source_ip}:{flow.source_port ?? '–'}</code><small>→ {flow.destination_ip}:{flow.destination_port ?? '–'}</small></td>
      <td>{flow.protocol}<small>External service {flow.service_port ?? 'unknown'}</small></td>
      <td>{(flow.packet_count ?? 0).toLocaleString()} packets<small>{formatBytes(flow.total_bytes)}</small></td>
      <td>{flow.has_payload ? <><span>{formatBytes(flow.payload_length)}</span><small>entropy {formatValue(flow.payload_entropy)} · printable {flow.payload_printable_ratio === undefined ? 'unknown' : `${Math.round(flow.payload_printable_ratio * 100)}%`}</small><small className="hash-value">SHA-256 {flow.payload_hash?.slice(0, 16)}… · SimHash {flow.payload_simhash ?? 'unavailable'}</small></> : <span className="muted">No payload</span>}</td>
      <td>{flow.current_label ? <><span className={`badge ${flow.current_label.verdict === 'C2' ? 'critical' : 'low'}`}>{flow.current_label.verdict}</span><small>{flow.current_label.confidence} · {fmt(flow.current_label.created_at)}</small><small>{flow.current_label.note}</small></> : <span className="muted">Unreviewed</span>}</td>
      <td><div className="row-actions"><button type="button" className="secondary" disabled={!flow.has_payload || preview.isPending} aria-label={`Preview payload ${flow.flow_id}`} onClick={() => preview.mutate()}>{preview.isPending ? 'Loading…' : 'Preview payload'}</button><button type="button" className="danger" aria-label={`Mark C2 ${flow.flow_id}`} onClick={() => startReview('C2')}>Mark C2</button><button type="button" className="secondary" aria-label={`Mark benign ${flow.flow_id}`} onClick={() => startReview('BENIGN')}>Mark benign</button>{flow.current_label?.verdict === 'C2' && <button type="button" className="secondary" disabled={guidance.isPending} aria-label={`탐지 조정 가이드 ${flow.flow_id}`} onClick={() => guidance.mutate()}>{guidance.isPending ? '가이드 계산 중…' : '탐지 조정 가이드'}</button>}</div></td>
    </tr>
    {(preview.data || preview.error) && <tr className="expanded-row"><td colSpan={8}><section aria-label={`Payload preview ${flow.flow_id}`} className="payload-preview"><div className="header-actions"><div><strong>Explicit payload preview</strong><small>{preview.data ? `${preview.data.sample_bytes} of ${preview.data.payload_length ?? preview.data.sample_bytes} bytes${preview.data.truncated ? ' (truncated)' : ''}` : 'Preview unavailable'}</small></div><button type="button" className="secondary" onClick={() => preview.reset()}>Close preview</button></div>{preview.error ? <p role="alert" className="error-text">{preview.error.message}</p> : <><p><strong>ASCII</strong></p><pre>{preview.data?.payload_ascii}</pre><p><strong>Hex</strong></p><pre>{preview.data?.payload_hex}</pre></>}</section></td></tr>}
    {verdict && <tr className="expanded-row"><td colSpan={8}><form className="flow-review-form" onSubmit={submit}><h3>Record {verdict} verdict</h3><div className="grid"><label>Confidence<select value={confidence} onChange={event => setConfidence(event.target.value as typeof confidence)}><option>CONFIRMED</option><option>HIGH</option><option>MEDIUM</option></select></label><label>Analyst note<textarea value={note} onChange={event => setNote(event.target.value)} maxLength={5000} rows={3} required /></label></div>{verdict === 'C2' && <fieldset><legend>Future detection</legend><label className="check"><input type="checkbox" checked={createSignature} onChange={event => setCreateSignature(event.target.checked)} disabled={!flow.has_payload} />Create payload signature</label>{createSignature && <label>Signature name<input value={signatureName} onChange={event => setSignatureName(event.target.value)} maxLength={200} required /></label>}<p className="muted">Exact payload matches alert at high confidence. Structural matches remain monitor-only and keep protocol, direction, and service-port guards.</p></fieldset>}{label.error && <p role="alert" className="error-text">{label.error.message}</p>}<div className="actions"><button disabled={label.isPending}>{label.isPending ? 'Saving…' : `Save ${verdict} label`}</button><button type="button" className="secondary" onClick={() => setVerdict(undefined)}>Cancel</button></div></form></td></tr>}
    {(guidance.data || guidance.error) && <tr className="expanded-row"><td colSpan={8}><DetectionGuidancePanel headingId={`detection-guidance-${flow.flow_id}`} guidance={guidance.data} error={guidance.error} reanalyzing={guidedReanalysis.isPending} reanalysisError={guidedReanalysis.error} onReanalyze={() => guidedReanalysis.mutate()} onClose={() => guidance.reset()} /></td></tr>}
    {notice && <tr className="expanded-row"><td colSpan={8}><p role="status">{notice}</p></td></tr>}
  </Fragment>;
}

function DetectionGuidancePanel({ headingId, guidance, error, reanalyzing, reanalysisError, onReanalyze, onClose }: { headingId: string; guidance?: DetectionGuidance; error?: Error | null; reanalyzing: boolean; reanalysisError?: Error | null; onReanalyze: () => void; onClose: () => void }) {
  return <section className="detection-guidance" aria-labelledby={headingId}><div className="header-actions"><div><h3 id={headingId}>탐지 조정 가이드</h3><p className="muted">수동 C2 판정을 동일 분석 데이터에 다시 대입해 실제 탐지 근거와 최소 점수 조정을 계산했습니다.</p></div><button type="button" className="secondary" onClick={onClose}>가이드 닫기</button></div>{error ? <p role="alert" className="error-text">{error.message}</p> : guidance && <><div className="guidance-score"><strong>{guidance.initially_detected ? '최초 분석에서 탐지됨' : '최초 분석 미탐'}</strong><span>현재 {guidance.current_score}점 · 후보 기준 {guidance.minimum_candidate_score}점 · {guidance.score_gap}점 부족</span>{guidance.suppressed_by_policy && <span className="badge critical">정책으로 억제됨</span>}</div><h4>성립한 탐지 조건</h4>{guidance.conditions.length ? <div className="guidance-grid">{guidance.conditions.map(condition => <article key={`${condition.detector}-${condition.evidence_type}`}><strong title={condition.evidence_type}>{evidenceLabel(condition.evidence_type)}</strong><small title={condition.detector}>{detectorLabel(condition.detector)}</small><span>기본 +{condition.contribution} · 적용 +{condition.weighted_contribution}</span><p>{condition.description}</p><div className="evidence-metrics">{Object.entries(condition.metrics).map(([key, value]) => <span key={key} title={key}><b>{metricLabel(key)}</b><output>{localizedMetricValue(value)}</output></span>)}</div></article>)}</div> : <p className="muted">현재 설정에서는 이 외부 IP에 대한 탐지 근거가 생성되지 않았습니다. 생성된 페이로드 서명 또는 탐지 조건 완화를 검토해야 합니다.</p>}<h4>점수 조정 내역</h4>{guidance.adjustments.length ? <ul className="adjustments">{guidance.adjustments.map((adjustment, index) => <li key={`${adjustment.kind}-${index}`}><strong className={adjustment.points < 0 ? 'critical' : 'low'}>{adjustment.points > 0 ? '+' : ''}{adjustment.points}</strong><span>{adjustmentLabel(adjustment.kind)} · {adjustment.explanation}</span></li>)}</ul> : <p className="muted">적용된 감점이나 추가 조정이 없습니다.</p>}<h4>권장 변경</h4>{guidance.recommendations.length ? <div className="guidance-recommendations">{guidance.recommendations.map((recommendation, index) => <article key={recommendation.id ?? `${recommendation.kind}-${recommendation.detector ?? index}`}><div className="header-actions"><strong>{recommendation.detector ? detectorLabel(recommendation.detector) : '탐지 정책 검토'}</strong><span className={`badge ${recommendation.risk === 'HIGH' ? 'critical' : 'medium'}`}>오탐 위험 {recommendation.risk}</span></div><p>{recommendation.rationale}</p><small>예상 {recommendation.projected_score}점 · +{recommendation.score_gain}점</small><small>{recommendation.risk_note}</small></article>)}</div> : <p className="muted">현재 설정에서 추가 점수 조정이 필요하지 않습니다.</p>}{guidance.warnings.map(warning => <p className="guidance-warning" key={warning}>주의: {warning}</p>)}<div className="guidance-actions"><button type="button" disabled={reanalyzing || !guidance.recommendations.some(item => item.kind === 'DETECTOR_WEIGHT' || item.kind === 'MINIMUM_SCORE')} onClick={onReanalyze}>{reanalyzing ? '재분석 생성 중…' : '추천 설정으로 재분석'}</button>{reanalysisError && <p role="alert" className="error-text">{reanalysisError.message}</p>}</div></>}</section>;
}

function PayloadSignatures() {
  const query = useQuery<List<PayloadSignature>, Error>({ queryKey: ['payload-signatures'], queryFn: () => api.get('/payload-signatures?page_size=200') });
  return <><header><p className="eyebrow">ANALYST-GUIDED DETECTION</p><h1>Payload signatures</h1><p className="muted">Manage versioned signatures created from confirmed C2 flows. Disabled signatures retain their provenance but are excluded from future analysis snapshots.</p></header><AsyncState query={query} empty={data => items(data).length === 0}>{data => <div className="table-wrap"><table aria-label="Payload signatures"><thead><tr><th>Signature</th><th>Status</th><th>Guards</th><th>Match features</th><th>Thresholds</th><th>Provenance</th><th>Manage</th></tr></thead><tbody>{items(data).map(signature => <PayloadSignatureRow key={signature.id} signature={signature} />)}</tbody></table></div>}</AsyncState></>;
}

function PayloadSignatureRow({ signature }: { signature: PayloadSignature }) {
  const client = useQueryClient();
  const [editing, setEditing] = useState(false);
  const update = useMutation<PayloadSignature, Error, Partial<PayloadSignature>>({
    mutationFn: changes => api.patch(`/payload-signatures/${signature.id}`, changes),
    onSuccess: () => {
      setEditing(false);
      client.invalidateQueries({ queryKey: ['payload-signatures'] });
    },
  });
  const remove = useMutation({
    mutationFn: () => api.delete(`/payload-signatures/${signature.id}`),
    onSuccess: () => {
      client.invalidateQueries({ queryKey: ['payload-signatures'] });
    },
  });
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    update.mutate({
      name: String(form.get('name')),
      description: String(form.get('description') ?? ''),
      length_tolerance_ratio: Number(form.get('length_tolerance_ratio')),
      entropy_tolerance: Number(form.get('entropy_tolerance')),
      simhash_max_distance: Number(form.get('simhash_max_distance')),
    });
  };
  return <Fragment>
    <tr>
      <td><strong>{signature.name}</strong><small>{signature.description || 'No description'}</small><small>Version {signature.version}</small></td>
      <td><span className={`badge ${signature.enabled ? 'online' : 'offline'}`}>{signature.enabled ? 'ENABLED' : 'DISABLED'}</span></td>
      <td>{signature.protocol ?? 'Any protocol'}<small>{signature.direction ?? 'Any direction'} · port {signature.service_port ?? 'any'}</small></td>
      <td>Exact SHA-256<small>{signature.payload_prefix_hash || signature.payload_simhash ? 'Structural comparison available' : 'Exact only'}</small><small className="hash-value">{signature.payload_hash?.slice(0, 20)}…</small></td>
      <td>Length ±{Math.round(signature.length_tolerance_ratio * 100)}%<small>Entropy ±{signature.entropy_tolerance} · SimHash ≤ {signature.simhash_max_distance}</small></td>
      <td><Link to={`/analyses/${signature.source_job_id}`}>Source analysis</Link><small>Flow {signature.source_flow_id}</small><small>{fmt(signature.created_at)} · {signature.created_by ?? 'analyst'}</small></td>
      <td><div className="row-actions"><button type="button" className={signature.enabled ? 'danger' : ''} disabled={update.isPending} aria-label={`${signature.enabled ? 'Disable' : 'Enable'} ${signature.name}`} onClick={() => update.mutate({ enabled: !signature.enabled })}>{signature.enabled ? 'Disable' : 'Enable'}</button><button type="button" className="secondary" aria-label={`Edit ${signature.name}`} onClick={() => { update.reset(); setEditing(true); }}>Edit</button><button type="button" className="danger" aria-label={`Delete ${signature.name}`} disabled={remove.isPending} onClick={() => remove.mutate()}>Delete</button></div>{update.error && !editing && <p role="alert" className="error-text">{update.error.message}</p>}{remove.error && <p role="alert" className="error-text">{remove.error.message}</p>}</td>
    </tr>
    {editing && <tr className="expanded-row"><td colSpan={7}><form className="flow-review-form" onSubmit={submit}><h3>Edit payload signature</h3><div className="grid"><label>Name<input name="name" defaultValue={signature.name} maxLength={200} required /></label><label>Description<textarea name="description" defaultValue={signature.description} maxLength={2000} rows={3} /></label><label>Length tolerance ratio<input name="length_tolerance_ratio" type="number" min="0" max="1" step="0.01" defaultValue={signature.length_tolerance_ratio} required /></label><label>Entropy tolerance<input name="entropy_tolerance" type="number" min="0" max="4" step="0.01" defaultValue={signature.entropy_tolerance} required /></label><label>SimHash maximum distance<input name="simhash_max_distance" type="number" min="0" max="32" defaultValue={signature.simhash_max_distance} required /></label></div><p className="muted">Saving creates the next signature version. Existing completed analyses keep their original snapshot.</p>{update.error && <p role="alert" className="error-text">{update.error.message}</p>}<div className="actions"><button disabled={update.isPending}>{update.isPending ? 'Saving…' : 'Save signature'}</button><button type="button" className="secondary" onClick={() => setEditing(false)}>Cancel</button></div></form></td></tr>}
  </Fragment>;
}

function Allowlist() {
  const client = useQueryClient();
  const q = useQuery<List<AllowEntry>, Error>({ queryKey: ['allowlist'], queryFn: () => api.get('/allowlist') });
  const add = useMutation({ mutationFn: (body: unknown) => api.post('/allowlist', body), onSuccess: () => client.invalidateQueries({ queryKey: ['allowlist'] }) });
  const remove = useMutation({ mutationFn: (id: string) => api.delete(`/allowlist/${id}`), onSuccess: () => client.invalidateQueries({ queryKey: ['allowlist'] }) });
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = event.currentTarget;
    const body: Record<string, FormDataEntryValue | boolean> = Object.fromEntries(new FormData(form).entries());
    if (!body.expires_at) delete body.expires_at;
    body.enabled = true;
    add.mutate(body, { onSuccess: () => form.reset() });
  };
  return <>
    <header><p className="eyebrow">FALSE-POSITIVE CONTROL</p><h1>Exceptions and infrastructure policies</h1></header>
    <section className="panel compact">
      <p><strong>IP, CIDR, domain, and fingerprint entries fully suppress matching candidates.</strong></p>
      <p className="muted">Trusted DNS/NTP policies reduce score only when the registered IP also matches UDP/53 or UDP/123. Protocol or port alone never suppresses a candidate.</p>
    </section>
    <form className="panel form-inline" onSubmit={submit}>
      <label>Type<select name="type"><option value="IP">IP — fully suppress</option><option value="CIDR">CIDR — fully suppress</option><option value="DOMAIN_SUFFIX">Domain suffix — fully suppress</option><option value="TLS_FINGERPRINT">TLS fingerprint — fully suppress</option><option value="CERT_FINGERPRINT">Certificate fingerprint — fully suppress</option><option value="TRUSTED_DNS">Trusted DNS — UDP/53 score adjustment</option><option value="TRUSTED_NTP">Trusted NTP — UDP/123 score adjustment</option></select></label>
      <label>Value<input name="value" required /></label>
      <label>Description<input name="description" required /></label>
      <label>Expires at<input name="expires_at" type="datetime-local" /></label>
      <button disabled={add.isPending}>{add.isPending ? 'Adding…' : 'Add entry'}</button>
      {add.error && <p role="alert" className="error-text">{add.error.message}</p>}
    </form>
    <AsyncState query={q}>{data => items(data).length ? <ul className="entries">{items(data).map(entry => <li key={entry.id}><code>{entry.type}</code><strong>{entry.value}</strong><span>{entry.description}</span>{entry.expires_at && <small>Expires {fmt(entry.expires_at)}</small>}<button className="danger" aria-label={`Delete ${entry.value}`} onClick={() => remove.mutate(entry.id)}>Delete</button></li>)}</ul> : <div className="state">No allowlist entries</div>}</AsyncState>
  </>;
}

export default function App() { const authenticated = Boolean(localStorage.getItem('c2hunter-token')); return <Routes><Route path="/login" element={<Login/>}/><Route path="*" element={!authenticated ? <Navigate to="/login" replace/> : <Shell><Routes><Route path="/" element={<Dashboard/>}/><Route path="/sensors" element={<Sensors/>}/><Route path="/sensors/:id" element={<SensorDetail/>}/><Route path="/external-sensors" element={<ExternalSensors/>}/><Route path="/external-sensors/enroll" element={<EnrollSensor/>}/><Route path="/analyses" element={<AnalysisHistory/>}/><Route path="/analyses/new" element={<NewAnalysis/>}/><Route path="/analyses/upload" element={<PcapUpload/>}/><Route path="/analyses/:id" element={<JobDetail/>}/><Route path="/candidates" element={<Candidates/>}/><Route path="/candidates/:id" element={<CandidateDetail/>}/><Route path="/payload-signatures" element={<PayloadSignatures/>}/><Route path="/allowlist" element={<Allowlist/>}/><Route path="*" element={<div className="state"><h1>Page not found</h1><Link to="/">Return to dashboard</Link></div>}/></Routes></Shell>}/></Routes>; }
