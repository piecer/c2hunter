# C2Hunter 데이터 모델

## 1. 모델링 원칙

- 모든 시각은 UTC `timestamptz`/고정밀 timestamp로 저장하고 원 센서 시각과 보정 offset을 함께 보존한다.
- 외부 API ID는 UUID/ULID, Sensor ID는 사용자가 제공하는 전역 고유 문자열을 사용한다.
- IP는 문자열이 아니라 PostgreSQL `inet`/ClickHouse IPv4·IPv6 타입으로 정규화한다.
- 분석 재현성을 위해 job의 센서 선택, 내부 CIDR, detector 버전, threshold, allowlist를 snapshot으로 고정한다.
- Flow 대용량 행은 ClickHouse, 관계·상태·권한·감사는 PostgreSQL, binary는 MinIO에 둔다.
- soft reference인 PCAP은 만료될 수 있으며 결과에는 `AVAILABLE/EXPIRED/DELETED/FAILED`를 명시한다.

## 2. PostgreSQL 제어 모델

### 2.1 Identity/RBAC

| 엔터티 | 핵심 필드/제약 |
|---|---|
| `users` | `id`, unique `username`, `password_hash` 또는 OIDC subject, `active`, timestamps; 평문 비밀번호 금지 |
| `roles` | enum `ADMIN, ANALYST, VIEWER, SENSOR` |
| `user_roles` | `(user_id, role)` unique |
| `sensor_credentials` | `sensor_id`, certificate serial/fingerprint, expiry, revoked_at; 개인키 저장 금지 |

### 2.2 Sensor

| 엔터티 | 핵심 필드/제약 |
|---|---|
| `sensors` | unique `sensor_id`, name, hostname, agent/os/kernel version, capabilities JSON, enabled, reported_status, derived_status, current_time, clock_offset_ms, available_disk_bytes, drop stats, last_heartbeat_at, last_error |
| `sensor_interfaces` | id, sensor FK, name, MAC, direction enum, VLAN-direction map, BPF/rule metadata; `(sensor_id,name)` unique |
| `sensor_heartbeats` | sensor FK, observed/reported time, status, CPU/memory/disk, active jobs, rx/drop count, pending bytes, last_error; time partition/30일 보관 |
| `sensor_groups` | id, unique name, description |
| `sensor_group_members` | `(group_id,sensor_id)` unique |
| `sensor_tags` | `(sensor_id,key,value)` unique |
| `sensor_commands` | id, sensor/job FK, type, payload, status, attempt, issued/acked/completed time, error; command ID로 멱등 |

`derived_status`는 heartbeat timeout/clock skew를 반영한다. 2초 초과 clock skew는 `DEGRADED`이며 원 reported status를 덮어쓰지 않는다.

### 2.3 분석·캡처

| 엔터티 | 핵심 필드/제약 |
|---|---|
| `analysis_jobs` | id, owner, name/analyst note, unique `(owner,idempotency_key)`, mode(`LIVE/HISTORICAL/REANALYSIS/PCAP_UPLOAD`), source type/upload metadata, current_status, capture/analysis parameter snapshot JSON, dataset FK, created/updated/started/completed time, cancellation, partial/failure summary |
| `analysis_job_sensors` | `(job_id,sensor_id)` unique, source group, command/status, packet/byte/flow counts, loss count, capture/upload/ingest times, failure code/detail |
| `job_state_transitions` | id, job FK, from/to status, occurred_at, actor type/id, reason/error code; append-only |
| `capture_datasets` | id, start/end, immutable flag, selected sensors, completeness, flow watermark, pcap availability |
| `analysis_runs` | id, job/dataset FK, profile and detector-version snapshot, internal networks, allowlist snapshot timestamp/hash, started/completed time, warning JSON |
| `ingest_batches` | unique `(sensor_id,batch_id)`, job/dataset, schema version, checksum, row count, byte count, status, received/committed time; 중복 ACK ledger |

Job 상태 enum은 `CREATED, WAITING_FOR_SENSOR, CAPTURING, UPLOADING, INGESTING, ANALYZING, COMPLETED, PARTIALLY_COMPLETED, FAILED, CANCELLED`다. terminal 상태는 되돌리지 않는다.

이력 화면에서 수정 가능한 값은 `name`과 analyst note뿐이다. source/dataset, capture·analysis snapshot, 시간 범위, 후보와 evidence는 불변이며 탐지 조건 변경은 새 `analysis_runs`를 만드는 reanalysis로 처리한다. 사용자가 terminal job을 명시적으로 삭제하면 해당 job의 후보와 생성 export를 함께 삭제하지만 append-only 삭제 감사 이벤트는 유지한다. 보관 정책에 의한 PCAP 만료는 이 명시적 job 삭제와 달리 후보를 삭제하지 않는다.

캡처 파라미터 snapshot은 시작/종료/기간/packet·byte limit, directions, BPF, src/dst CIDR와 port, protocols, IP version, payload/PCAP flags, timeout을 포함한다. 여러 종료 조건 중 먼저 충족된 이유를 `analysis_job_sensors.stop_reason`에 기록한다.

### 2.4 후보·증거

| 엔터티 | 핵심 필드/제약 |
|---|---|
| `candidates` | id, run FK, candidate IP, score(0..100), severity, first/last seen, protocols/ports, distinct host/sensor count, false-positive notes, confidence/warnings; `(run_id,candidate_ip)` unique |
| `evidence` | id, candidate FK, detector name/version, type, raw score, capped contribution, description, first/last seen, metrics JSON, confidence, false-positive note |
| `candidate_internal_hosts` | candidate FK, internal IP, first/last seen, connection/packet/byte count |
| `candidate_sensor_observations` | candidate/sensor FK, first/last seen, flow count, clock offset/warning |
| `attack_targets` | candidate FK, target IP/port/protocol, first/last seen, peak PPS, baseline PPS, increase ratio, affected host count |
| `score_adjustments` | candidate FK, type(`ALLOWLIST/PUBLIC_DNS_NTP/CDN_CLOUD/INTERNAL_SERVER/SINGLE_HOST/LOW_SAMPLE`), points, rule/allowlist FK, explanation |

Evidence `metrics`에는 detector 입력값을 machine-readable 형태로 보존한다. 최종 점수만 저장해 계산 근거를 잃지 않는다.

### 2.5 Allowlist

`allowlist_entries`: id, type(`IP/CIDR/DOMAIN_SUFFIX/TLS_FINGERPRINT/CERT_FINGERPRINT`), normalized value, description, expires_at, enabled, creator, created/updated time. IP/CIDR 명시 match는 후보 제외, 다른 공용/업무 인프라 정책은 score adjustment로 처리한다. `allowlist_suppression_stats`에 run, entry, match count, candidate IP hash/reference, timestamp를 남겨 제외 결과도 감사 가능하게 한다.

### 2.6 PCAP/object

| 엔터티 | 핵심 필드/제약 |
|---|---|
| `pcap_objects` | id, job/dataset/sensor FK, server-generated object key, start/end, size, SHA-256, packet count, rotation reason, state, retention/delete time |
| `flow_pcap_refs` | flow identity/range와 object FK, byte/time index 힌트 |
| `pcap_exports` | id, requester, candidate/job FK, normalized filter JSON, status, estimated/actual size, output object FK, expires_at, error |
| `download_audits` | export/object/user, request IP, time, result, bytes |

Export 필터는 candidate IP, internal host IP, time range, port, protocol, direction, sensor를 포함한다. signed URL 자체를 장기 저장하지 않고 만료 시간만 기록한다.

### 2.7 감사·설정·보관

`audit_logs`: actor user/sensor, occurred_at, source IP, action, target type/id, result, request ID, safe detail JSON. 로그인, 분석 생성/취소, download, allowlist 변경, sensor 등록/해제, 설정/권한 변경, 삭제를 기록하며 secret/payload는 넣지 않는다.

`retention_policies`: data type별 days와 enabled. 기본값은 Raw PCAP 7일, Flow 30일, 분석 결과 180일, 감사 365일, heartbeat 30일이다. `cleanup_runs`는 policy, cutoff, scanned/deleted/error count를 기록한다.

## 3. ClickHouse 분석 모델

### 3.1 `flows`

Flow logical key:

```text
(sensor_id, direction, ip_version, source_ip, destination_ip,
 source_port, destination_port, transport_protocol)
```

동일 key라도 idle timeout(기본 60초) 또는 capture 경계마다 별도 `flow_id`를 만든다.

필수 컬럼:
- `flow_id`, `dataset_id`, `job_id`, `capture_job_id`, `sensor_id`, `direction`
- `ip_version`, `source_ip`, `destination_ip`, nullable ports, `transport_protocol`
- `start_time`, `end_time`, `packet_count`, `total_bytes`
- `packet_size_min/max/avg`, `tcp_flag_counts`
- `bidirectional`, `payload_length_min/max/avg`
- `first_payload_hash`, `last_payload_hash`, `pcap_object_id`
- `ingest_batch_id`, `schema_version`

권장 partition/order: 월/일 partition, `(dataset_id, destination_ip, start_time, sensor_id)` order. 분석은 dataset/time predicate를 항상 포함한다.

### 3.2 프로토콜 메타데이터

별도 sparse tables를 사용한다.

- `dns_events`: query name/type, rcode, answer IP, TTL, TXT length/hash, request/response time.
- `http_events`: method, host, URI path, user-agent, status, content-length. body 제외.
- `tls_events`: SNI, ALPN, TLS version, cipher suites hash/list, hello fingerprints, certificate subject/issuer/SHA-256.
- `unknown_protocol_features`: first-N hash, payload length/entropy, bounded packet-size sequence, request/response ratio.

공통 키는 dataset/job/sensor/flow, event time, src/dst IP/port다. 민감 원문 대신 hash/statistics를 우선한다.

### 3.3 중복 제거와 관찰 보존

- `packet_fingerprints`: dataset, normalized 5-tuple, IP ID, TCP sequence, payload length/hash, timestamp bucket으로 dedup key를 계산한다.
- `packet_observations`: dedup key, sensor/interface, observed timestamp, direction을 보존한다.
- 정확한 패킷 필드가 없는 집계 Flow에서는 dedup confidence를 기록하고 무리하게 제거하지 않는다.
- logical count는 dedup canonical record에서 계산하되 multi-sensor detector는 observation table을 사용한다.

## 4. 도메인 값

### 방향
`INBOUND, OUTBOUND, BIDIRECTIONAL, UNKNOWN`. 판별 근거를 `direction_source`(`INTERFACE/VLAN/CIDR/BPF_RULE/NONE`)로 보존한다.

### Sensor 상태
`ONLINE, OFFLINE, DEGRADED, CAPTURING, ERROR`.

### Candidate severity
- 0–39 `LOW`
- 40–59 `MEDIUM`
- 60–79 `HIGH`
- 80–100 `CRITICAL`

### 비동기 export/ingest 상태
`PENDING, RUNNING, COMPLETED, FAILED, CANCELLED`를 공통으로 쓰되 각 리소스의 허용 전이를 서비스 계층에서 제한한다.

## 5. 불변식

1. `candidate.score`는 0~100이며 evidence와 adjustments의 재계산으로 설명 가능해야 한다.
2. Candidate는 하나의 immutable analysis run에 속한다.
3. 동일 owner/idempotency key는 하나의 analysis job만 가리킨다.
4. 동일 sensor/batch ID는 한 번만 commit된다.
5. `UNKNOWN` 방향을 추정값으로 변경하지 않는다.
6. dedup 후에도 관찰 센서 집합은 손실하지 않는다.
7. terminal job 상태 이후 새 state transition은 취소/재시도로 변경되지 않는다.
8. PCAP 삭제는 후보/증거를 cascade 삭제하지 않고 availability만 갱신한다.
9. 감사 로그는 append-only이고 비밀·Payload 원문을 포함하지 않는다.

## 6. API read model

후보 상세 응답은 Candidate + Evidence + InternalHost + SensorObservation + AttackTarget + PcapObject availability를 조합한다. 목록은 PostgreSQL summary를 사용하고 Flow 목록/차트만 ClickHouse를 조회하여 일반 응답 5초 목표를 지킨다. 모든 목록은 cursor 또는 page pagination, allowlisted filter, deterministic sorting을 적용한다.

## 7. 마이그레이션·보관

PostgreSQL은 Alembic, ClickHouse는 순번 migration으로 schema version을 관리한다. 파괴적 변경은 producer/consumer 호환 기간을 둔다. cleanup은 PCAP→Flow→heartbeat/result/audit의 각 정책별 batch job으로 실행하며 삭제량/실패를 감사한다. 결과가 참조하는 PCAP이 만료되면 `EXPIRED`를 즉시 표시한다.
