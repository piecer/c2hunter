import { FormEvent, ReactNode, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, Navigate, Route, Routes, useNavigate, useParams } from 'react-router-dom';
import { api } from './api';
import './styles.css';

type List<T> = { items: T[] } | T[];
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
type Job = { id: string; name: string; description?: string; status: string; mode?: string; source_type?: string; source?: JobSource; created_at?: string; updated_at?: string; completed_at?: string; start_time?: string; end_time?: string; sensor_ids?: string[]; progress_percent?: number; packet_count?: number; flow_count?: number; candidate_count?: number; warnings?: string[] };
type Candidate = { id: string; job_id: string; candidate_ip: string; score: number; severity: string; distinct_internal_hosts: number; sensor_ids: string[]; protocols: string[]; ports: number[]; first_seen: string; last_seen: string; evidence: { type: string; score: number; description: string }[]; traffic_series?: number[]; internal_hosts?: string[]; related_attack_targets?: string[] };
type AllowEntry = { id: string; type: string; value: string; description?: string; expires_at?: string };
const sensorStatus = (sensor: Sensor) => sensor.status ?? sensor.derived_status ?? 'OFFLINE';
const idempotencyKey = () => `${Date.now()}-${crypto.randomUUID()}`;
const terminalStatuses = new Set(['COMPLETED', 'PARTIALLY_COMPLETED', 'FAILED', 'CANCELLED']);

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
  return <div className="shell"><aside><div className="brand">C2<span>Hunter</span></div><nav aria-label="Primary"><Link to="/">Dashboard</Link><Link to="/sensors">Sensors</Link><Link to="/external-sensors">External sensors</Link><Link className="nav-child" to="/external-sensors/enroll">Enroll sensor</Link><Link to="/analyses">Analysis history</Link><Link className="nav-child" to="/analyses/new">New analysis</Link><Link className="nav-child" to="/analyses/upload">Upload PCAP</Link><Link to="/candidates">Candidates</Link><Link to="/allowlist">Allowlist</Link></nav><button className="quiet" onClick={() => { localStorage.removeItem('c2hunter-token'); navigate('/login'); }}>Sign out</button></aside><main className="content">{children}</main></div>;
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
    const form = new FormData(event.currentTarget);
    const query = new URLSearchParams({
      name: String(form.get('name')),
      description: String(form.get('description') ?? ''),
      filename: file.name,
      internal_networks: String(form.get('internal_networks')),
      minimum_candidate_score: String(form.get('score')),
      minimum_distinct_clients: String(form.get('hosts')),
      periodicity_min_samples: String(form.get('samples')),
      idempotency_key: idempotencyKey(),
    });
    mutation.mutate({ file, query });
  };
  return <><header className="header-actions"><div><p className="eyebrow">OFFLINE INVESTIGATION</p><h1>Upload PCAP</h1><p className="muted">Analyze an existing capture with the same C2 correlation and scoring pipeline used for sensor traffic.</p></div><Link to="/analyses">View analysis history</Link></header><form className="panel form" onSubmit={submit}><label>Analysis name<input name="name" required maxLength={200} /></label><label>Analyst note<textarea name="description" rows={3} maxLength={5000} placeholder="Case, ticket, or collection context" /></label><label>Capture file<input name="pcap" type="file" accept=".pcap,.pcapng,.cap,application/vnd.tcpdump.pcap,application/octet-stream" onChange={event => setFile(event.target.files?.[0])} required /></label>{file && <div className="file-summary" role="status"><strong>{file.name}</strong><span>{formatBytes(file.size)}</span></div>}<div className="grid"><label>Internal networks<input name="internal_networks" defaultValue="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16" required /></label><label>Minimum score<input name="score" type="number" min="0" max="100" defaultValue="0" required /></label><label>Minimum internal hosts<input name="hosts" type="number" min="2" defaultValue="3" required /></label><label>Beacon minimum samples<input name="samples" type="number" min="3" defaultValue="5" required /></label></div><p className="muted">Supported containers: classic PCAP and PCAPNG. Supported packet links include Ethernet, raw IP, Linux cooked capture v1/v2, and loopback. The default server limit is 100 MiB and 2,000,000 packets.</p>{(validationError || mutation.error) && <p role="alert" className="error-text">{validationError || mutation.error?.message}</p>}<button disabled={mutation.isPending}>{mutation.isPending ? 'Uploading and analyzing…' : 'Upload and analyze'}</button></form></>;
}

function NewAnalysis() {
  const navigate = useNavigate(); const sensors = useQuery<List<Sensor>, Error>({ queryKey: ['sensors'], queryFn: () => api.get('/sensors') }); const mutation = useMutation({ mutationFn: (body: unknown) => api.post<Job>('/analysis-jobs', body), onSuccess: j => navigate(`/analyses/${j.id}`) });
  const submit = (e: FormEvent<HTMLFormElement>) => { e.preventDefault(); const f = new FormData(e.currentTarget); const start = new Date(); const end = new Date(start.getTime() + Number(f.get('duration')) * 1000); mutation.mutate({ name: f.get('name'), idempotency_key: idempotencyKey(), sensor_ids: f.getAll('sensor_ids'), mode: f.get('mode'), start_time: start.toISOString(), end_time: end.toISOString(), internal_networks: String(f.get('internal_networks')).split(',').map(value => value.trim()).filter(Boolean), capture: { duration_seconds: Number(f.get('duration')), max_packets: Number(f.get('max_packets')), directions: f.getAll('directions'), bpf_filter: f.get('bpf'), store_pcap: f.get('store_pcap') === 'on' }, analysis: { profile: 'ddos_botnet', minimum_candidate_score: Number(f.get('score')), minimum_distinct_clients: Number(f.get('hosts')) } }); };
  return <><header><p className="eyebrow">INVESTIGATION</p><h1>New analysis</h1></header><form className="panel form" onSubmit={submit}><label>Analysis name<input name="name" required /></label><fieldset><legend>Sensors</legend><AsyncState query={sensors}>{d => <>{items(d).map(s => <label className="check" key={s.sensor_id}><input type="checkbox" name="sensor_ids" value={s.sensor_id} aria-label={s.name}/>{s.name}</label>)}</>}</AsyncState></fieldset><div className="grid"><label>Data source<select name="mode"><option value="LIVE">Live capture</option><option value="HISTORICAL">Historical</option></select></label><label>Duration (seconds)<input name="duration" type="number" min="1" defaultValue="300" /></label><label>Internal networks<input name="internal_networks" defaultValue="10.0.0.0/8" required /></label><label>Maximum packets<input name="max_packets" type="number" min="1" defaultValue="2000000" /></label><label>BPF filter<input name="bpf" defaultValue="ip" /></label><label>Minimum score<input name="score" type="number" min="0" max="100" defaultValue="60" /></label><label>Minimum internal hosts<input name="hosts" type="number" min="2" defaultValue="5" /></label></div><fieldset><legend>Directions</legend>{['INBOUND','OUTBOUND'].map(v => <label className="check" key={v}><input type="checkbox" name="directions" value={v} defaultChecked/>{v}</label>)}</fieldset><label className="check"><input type="checkbox" name="store_pcap" defaultChecked/>Store PCAP</label>{mutation.error && <p role="alert">{mutation.error.message}</p>}<button disabled={mutation.isPending}>{mutation.isPending ? 'Starting…' : 'Start analysis'}</button></form></>;
}

function JobDetail() {
  const { id } = useParams();
  const [notice, setNotice] = useState('');
  const q = useQuery<Job, Error>({ queryKey: ['job', id], queryFn: () => api.get(`/analysis-jobs/${id}`), refetchInterval: 3000 });
  const cancel = useMutation({ mutationFn: () => api.post(`/analysis-jobs/${id}/cancel`, { reason: 'operator requested from web console' }), onSuccess: () => { setNotice('Cancellation requested'); q.refetch(); } });
  return <AsyncState query={q}>{j => { const terminal = terminalStatuses.has(j.status); return <><header className="header-actions"><div><p className="eyebrow">ANALYSIS DETAIL</p><h1>{j.name}</h1><span className={`badge ${j.status.toLowerCase()}`}>{j.status}</span></div><Link to="/analyses">Back to analysis history</Link></header>{j.description && <section className="panel"><h2>Analyst note</h2><p>{j.description}</p></section>}<section className="panel"><label>Progress <progress value={terminal ? 100 : j.progress_percent ?? 0} max="100">{terminal ? 100 : j.progress_percent}%</progress></label><section className="metrics compact"><article><strong>{j.packet_count ?? 0}</strong><span>Packets</span></article><article><strong>{j.flow_count ?? 0}</strong><span>Flows</span></article><article><strong>{j.candidate_count ?? 0}</strong><span>Candidates</span></article></section>{j.warnings?.map(warning => <p className="warning" key={warning}>{warning}</p>)}{!terminal && <button className="danger" disabled={cancel.isPending} onClick={() => cancel.mutate()}>{cancel.isPending ? 'Cancelling…' : 'Cancel analysis'}</button>}{cancel.error && <p role="alert" className="error-text">{cancel.error.message}</p>}{notice && <p role="status">{notice}</p>}</section><section className="grid compact"><article className="panel"><h2>Source</h2><dl><dt>Type</dt><dd>{j.source_type === 'PCAP_UPLOAD' ? 'PCAP upload' : j.mode ?? 'Sensor capture'}</dd><dt>File</dt><dd>{j.source?.filename ?? 'Sensor dataset'}</dd><dt>Size</dt><dd>{formatBytes(j.source?.size_bytes)}</dd><dt>SHA-256</dt><dd className="hash-value">{j.source?.sha256 ?? 'Not applicable'}</dd></dl></article><article className="panel"><h2>Timeline</h2><dl><dt>Observed from</dt><dd>{fmt(j.start_time)}</dd><dt>Observed to</dt><dd>{fmt(j.end_time)}</dd><dt>Created</dt><dd>{fmt(j.created_at)}</dd><dt>Completed</dt><dd>{fmt(j.completed_at)}</dd></dl></article></section></>; }}</AsyncState>;
}

function Candidates() { const q = useQuery<List<Candidate>, Error>({ queryKey: ['candidates'], queryFn: () => api.get('/candidates') }); return <><header><p className="eyebrow">DETECTION RESULTS</p><h1>Candidates</h1></header><AsyncState query={q} empty={d => items(d).length === 0}>{d => <div className="table-wrap"><table aria-label="C2 candidates"><thead><tr><th>Candidate</th><th>Score</th><th>Hosts</th><th>Sensors</th><th>Protocol / port</th><th>Observed</th><th>Primary evidence</th></tr></thead><tbody>{items(d).map(c => <tr key={c.id}><td><Link to={`/candidates/${c.id}`}>{c.candidate_ip}</Link><small className={c.severity.toLowerCase()}>{c.severity}</small></td><td><strong>{c.score}</strong></td><td>{c.distinct_internal_hosts}</td><td>{c.sensor_ids.length}</td><td>{c.protocols.join(', ')} / {c.ports.join(', ')}</td><td>{fmt(c.first_seen)} – {fmt(c.last_seen)}</td><td>{c.evidence[0]?.type}</td></tr>)}</tbody></table></div>}</AsyncState></>; }

function CandidateDetail() { const { id } = useParams(); const [notice, setNotice] = useState(''); const q = useQuery<Candidate, Error>({ queryKey: ['candidate', id], queryFn: () => api.get(`/candidates/${id}`) }); const exportPcap = useMutation({ mutationFn: () => api.post('/pcap-exports', { job_id: q.data?.job_id, candidate_id: id }), onSuccess: () => setNotice('PCAP export requested') }); const reanalyze = useMutation({ mutationFn: () => api.post(`/analysis-jobs/${q.data?.job_id}/reanalyze`, { idempotency_key: idempotencyKey() }), onSuccess: () => setNotice('Reanalysis created') }); return <AsyncState query={q}>{c => <><header><p className="eyebrow">CANDIDATE DETAIL</p><h1>{c.candidate_ip}</h1><span className={`badge ${c.severity.toLowerCase()}`}>{c.score} · {c.severity}</span></header><div className="grid"><section className="panel"><h2>Traffic over time</h2><MiniChart values={c.traffic_series ?? []} label="Traffic over time" /></section><section className="panel"><h2>Context</h2><p><b>Internal hosts:</b> {c.internal_hosts?.join(', ') || c.distinct_internal_hosts}</p><p><b>Sensors:</b> {c.sensor_ids.join(', ')}</p><p><b>Attack targets:</b> {c.related_attack_targets?.join(', ') || 'None identified'}</p></section></div><section className="panel"><h2>Detection evidence</h2>{c.evidence.map(e => <article className="evidence" key={e.type}><strong>{e.type}</strong><span>+{e.score}</span><p>{e.description}</p></article>)}<div className="actions"><button onClick={() => exportPcap.mutate()}>Export candidate PCAP</button><button className="secondary" onClick={() => reanalyze.mutate()}>Reanalyze</button></div>{notice && <p role="status">{notice}</p>}</section></>}</AsyncState>; }

function Allowlist() { const client = useQueryClient(); const q = useQuery<List<AllowEntry>, Error>({ queryKey: ['allowlist'], queryFn: () => api.get('/allowlist') }); const add = useMutation({ mutationFn: (body: unknown) => api.post('/allowlist', body), onSuccess: () => client.invalidateQueries({ queryKey: ['allowlist'] }) }); const remove = useMutation({ mutationFn: (id: string) => api.delete(`/allowlist/${id}`), onSuccess: () => client.invalidateQueries({ queryKey: ['allowlist'] }) }); const submit = (e: FormEvent<HTMLFormElement>) => { e.preventDefault(); const f = new FormData(e.currentTarget); add.mutate(Object.fromEntries(f.entries())); e.currentTarget.reset(); }; return <><header><p className="eyebrow">FALSE-POSITIVE CONTROL</p><h1>Allowlist</h1></header><form className="panel form-inline" onSubmit={submit}><label>Type<select name="type"><option>IP</option><option>CIDR</option><option>DOMAIN_SUFFIX</option><option>TLS_FINGERPRINT</option><option>CERT_FINGERPRINT</option></select></label><label>Value<input name="value" required /></label><label>Description<input name="description" /></label><label>Expires at<input name="expires_at" type="datetime-local" /></label><button>Add entry</button></form><AsyncState query={q}>{d => items(d).length ? <ul className="entries">{items(d).map(e => <li key={e.id}><code>{e.type}</code><strong>{e.value}</strong><span>{e.description}</span><button className="danger" aria-label={`Delete ${e.value}`} onClick={() => remove.mutate(e.id)}>Delete</button></li>)}</ul> : <div className="state">No allowlist entries</div>}</AsyncState></>; }

export default function App() { const authenticated = Boolean(localStorage.getItem('c2hunter-token')); return <Routes><Route path="/login" element={<Login/>}/><Route path="*" element={!authenticated ? <Navigate to="/login" replace/> : <Shell><Routes><Route path="/" element={<Dashboard/>}/><Route path="/sensors" element={<Sensors/>}/><Route path="/sensors/:id" element={<SensorDetail/>}/><Route path="/external-sensors" element={<ExternalSensors/>}/><Route path="/external-sensors/enroll" element={<EnrollSensor/>}/><Route path="/analyses" element={<AnalysisHistory/>}/><Route path="/analyses/new" element={<NewAnalysis/>}/><Route path="/analyses/upload" element={<PcapUpload/>}/><Route path="/analyses/:id" element={<JobDetail/>}/><Route path="/candidates" element={<Candidates/>}/><Route path="/candidates/:id" element={<CandidateDetail/>}/><Route path="/allowlist" element={<Allowlist/>}/><Route path="*" element={<div className="state"><h1>Page not found</h1><Link to="/">Return to dashboard</Link></div>}/></Routes></Shell>}/></Routes>; }
