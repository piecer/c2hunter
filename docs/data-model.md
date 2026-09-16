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
| `job_flow_records` | job ID PK, immutable normalized flow-record payload JSONB. job metadata와 물리적으로 분리하며 분석 Worker만 job ID로 로드 |
| `job_payload_signatures` | job ID PK, 해당 run에 고정한 활성 Payload signature snapshot JSONB. compact job metadata와 분리하며 Worker만 분석 시작 시 로드 |

`analysis.module=ddos_attack` 작업은 job metadata에 bounded `ddos_attack` 상세 report와
`ddos_attack_summary` 목록 projection을 저장한다. 별도 Candidate row를 만들지 않는다. full report는
작업 상세 및 inline/PCAP 생성 응답에서 반환하고 목록 응답에서는 제외한다. 재분석은 같은 immutable
flow payload를 참조하되 새 job과 threshold snapshot을 만든다.

Job 상태 enum은 `CREATED, WAITING_FOR_SENSOR, CAPTURING, UPLOADING, INGESTING, ANALYZING, COMPLETED, PARTIALLY_COMPLETED, FAILED, CANCELLED`다. terminal 상태는 되돌리지 않는다.

이력 화면에서 수정 가능한 값은 `name`과 analyst note뿐이다. source/dataset, capture·analysis snapshot, 시간 범위, 후보와 evidence는 불변이며 탐지 조건 변경은 새 `analysis_runs`를 만드는 reanalysis로 처리한다. 사용자가 terminal job을 명시적으로 삭제하면 해당 job의 후보와 생성 export를 함께 삭제하지만 append-only 삭제 감사 이벤트는 유지한다. 보관 정책에 의한 PCAP 만료는 이 명시적 job 삭제와 달리 후보를 삭제하지 않는다.

Stage 10의 `pcap_offset_index_jobs`는 공개 job 모델이 아닌 내부 LIVE-segment 작업 ledger다. finalized/retained LIVE segment marker, canonical sensor/job/object binding, queue status, attempt, retry time, lease token/expiry, stable terminal code만 저장한다. segment JSON의 내부 `index_intent_state`는 `PENDING/DEFERRED/COMPLETED/FAILED`이고 schema/parser contract version과 함께 task 전이 transaction에서 갱신된다. `COMPLETED/FAILED`는 terminal이라 reconciliation이 다시 admit하지 않고, `PENDING/DEFERRED`만 유실된 task 복구 대상이다. READY owner와 staging generation은 canonical LIVE source 삭제/보관 시 cascade되고, 연결되지 않은 archive source는 보존된다. 이 per-segment metadata는 optional이며 export가 Stage 12 전에는 조회하지 않는다.

Stage 11 posting lifecycle도 공개 analysis/export job이 아니라 내부 derived-data ledger다. `pcap_posting_index_intents` 상태는 `PENDING/DEFERRED/COMPLETED/FAILED`, `pcap_posting_index_jobs` 상태는 `QUEUED/RUNNING/COMPLETED/FAILED`다. intent의 terminal 상태는 자동 재-admit하지 않고, task의 만료 lease는 attempt 한도 안에서 recovery/retry한다. 이 상태나 내부 marker field는 REST/OpenAPI 응답에 노출하지 않는다.

캡처 파라미터 snapshot은 시작/종료/기간/packet·byte limit, directions, BPF, src/dst CIDR와 port, protocols, IP version, payload/PCAP flags, timeout을 포함한다. 여러 종료 조건 중 먼저 충족된 이유를 `analysis_job_sensors.stop_reason`에 기록한다.

### 2.4 후보·증거

| 엔터티 | 핵심 필드/제약 |
|---|---|
| `candidates` | id, run FK, candidate IP, score(0..100), severity, first/last seen, protocols/ports, distinct host/sensor count, false-positive notes, confidence/warnings; `(run_id,candidate_ip)` unique |
| `evidence` | id, candidate FK, detector name/version, type, raw score, capped contribution, description, first/last seen, metrics JSON, confidence, false-positive note |
| `candidate_internal_hosts` | candidate FK, internal IP, first/last seen, connection/packet/byte count |
| `candidate_sensor_observations` | candidate/sensor FK, first/last seen, flow count, clock offset/warning |
| `attack_targets` | candidate FK, target IP/port/protocol, first/last seen, peak PPS, baseline PPS, increase ratio, affected host count |
| `score_adjustments` | candidate FK, type(`ALLOWLIST/PUBLIC_DNS_NTP/CDN_CLOUD/SINGLE_HOST/LOW_SAMPLE/HIGH_VOLUME/DETECTOR_WEIGHT_*`), points, rule/allowlist FK, explanation |

Evidence `metrics`에는 detector 입력값을 machine-readable 형태로 보존한다. 최종 점수만 저장해 계산 근거를 잃지 않는다.

### 2.5 분석가 Flow 판정과 Payload signature

| 엔터티 | 핵심 필드/제약 |
|---|---|
| `flow_labels` | append-only id, job/flow ID, verdict(`C2/BENIGN`), confidence, note, 안전한 Flow/비가역 Payload 특징 snapshot, actor/time |
| `payload_signatures` | id, name/description, version, enabled, source job/flow/label, protocol/direction/service-port guard, Payload hash/prefix hash/length/entropy/printable ratio/SimHash, structural threshold, creator/timestamps |

라벨 정정은 기존 행 수정이 아니라 새 라벨 append이며 가장 최근 라벨이 현재 판정이다.
Signature 조건 변경은 version을 증가시키고 비활성화해도 provenance는 삭제하지 않는다.
동일 Payload hash에 대한 최신 `BENIGN` 라벨이 있으면 새 C2 signature 생성을 거부한다.
Payload 원문과 미리보기는 라벨, signature, job snapshot, 감사 로그에 저장하지 않는다.

### 2.6 Allowlist

`allowlist_entries`: id, type(`IP/CIDR/DOMAIN_SUFFIX/TLS_FINGERPRINT/CERT_FINGERPRINT/TRUSTED_DNS/TRUSTED_NTP`), normalized value, description, expires_at, enabled, creator, created/updated time. `expires_at`은 nullable이지만 지정 시 timezone을 포함한 미래 ISO 8601 시각만 허용하고 UTC로 정규화한다. IP/CIDR 명시 match는 후보 제외, 다른 공용/업무 인프라 정책은 score adjustment로 처리한다. `allowlist_suppression_stats`에 run, entry, match count, candidate IP hash/reference, timestamp를 남겨 제외 결과도 감사 가능하게 한다.

### 2.7 PCAP/object

| 엔터티 | 핵심 필드/제약 |
|---|---|
| `pcap_objects` | id, job/dataset/sensor FK, server-generated object key, start/end, size, SHA-256, packet count, rotation reason, state, retention/delete time. LIVE upload key는 `sensor-pcaps/{sensor_id}/{segment_id}/{generation}.pcap` 형태의 attempt 고유 immutable key이며 공개 filename/segment response는 그대로 유지 |
| uploaded source PCAP | `captures/{job_id}.pcap` server-generated key로 MinIO에 한 번 저장. normalized flow에는 기본적으로 raw packet hex를 중복 보관하지 않음 |
| `pcap_capture_source_versions` | canonical uploaded source별 authoritative durable identity: source/job ID, exact object key, immutable backend version ID, verified byte size/SHA-256, update time. capture upload 검증 후 PostgreSQL transaction에서 기록하며 publication/lookup은 이 row를 재검증 |
| `flow_pcap_refs` | flow identity/range와 object FK, byte/time index 힌트 |
| `pcap_offset_index_generations` | 내부 Stage 9 structural generation: build/source identity, source version/size/SHA-256, capture format, schema/parser contract versions, `STAGING/READY`, counts, index SHA-256, created time |
| `pcap_offset_index_interfaces` / `pcap_offset_index_packets` | generation-owned interface metadata와 canonical packet order의 record/data offset, captured/original/framed length, section/interface identity, raw timestamp ticks; generation 삭제 시 cascade |
| `pcap_offset_index_owners` | `(source_kind,source_id)`별 공개된 READY generation 하나를 가리키는 내부 metadata owner |
| `pcap_posting_index_intents` | `(source_kind,source_id)` PK와 `(source_kind,source_id,parent_structural_build_id)` unique; source-version row와 structural parent FK, immutable source identity/size/SHA, parent digest, structural/posting/filter contract versions, intent status/terminal attempt/error |
| `pcap_posting_index_jobs` | `(source_kind,source_id)` PK; 같은 source/parent intent composite FK, `QUEUED/RUNNING/COMPLETED/FAILED`, attempt/max attempts, next-attempt/order timestamps, opaque lease token/expiry, stable error |
| `pcap_posting_index_generations` | build ID PK; source-version FK와 structural-parent FK, `STAGING/READY`, exact source/parent/contracts binding, packet/supported/membership/dictionary/chunk/encoded-byte counts, complete dimensions, generation SHA-256, builder attempt/lease/expected prior owner |
| `pcap_posting_index_chunks` | generation FK; `(build_id,dimension,canonical_value,chunk_ordinal)` PK, first/last packet ordinal, membership count, delta-encoded ordinal bytes |
| `pcap_posting_index_owners` | `(source_kind,source_id,parent_structural_build_id)` PK와 unique build ID; composite FK로 그 exact source/parent generation의 한 READY owner만 publication |
| `pcap_exports` | 기존 sync/완료 artifact metadata: id, requester, requested job/candidate, resolved `source_job_id`, normalized filter, source manifest/count, terminal status, counters, format/filename, repository-computed immutable size/SHA-256, object key/blob, stable error, created time |
| `pcap_export_jobs` | durable lifecycle row: export/principal identity, optional principal-scoped idempotency key, request/coalesce fingerprints, requested/resolved source IDs, immutable source generation + ordered manifest JSON, canonical request/effective limits/policy version, estimated work, `QUEUED/RUNNING/COMPLETED/FAILED/CANCELLED`, execution mode, progress phase/high-water counters/percent, cancellation request/reason, attempt/max attempts/next availability, opaque lease token/expiry, public error, artifact metadata, queued/started/updated/completed/expiry timestamps |
| `download_audits` | export/object/user, request IP, time, result, bytes |

`pcap_export_jobs`는 export ID PK, nullable key의 `(principal_scope,idempotency_key)` unique, reusable state의 principal/coalesce uniqueness, `(status,next_attempt_at,queued_at)` claim order, `(status,lease_expires_at)` recovery, parent/source-job deletion-guard index를 가진다. 이들은 durable queue correctness index이며 Stage 9 packet index가 아니다. 기존 Stage 3–7 rows/object는 backfill하지 않고 terminal `execution_mode=SYNC`로 adapt한다.

Stage 9 structural index는 **offline canonical `PCAP_UPLOAD` source 전용** derived/best-effort 내부 데이터다. builder는 retained source 전체를 읽어 size/SHA/format과 packet 구조를 검증하고, canonical job metadata와 `pcap_capture_source_versions`의 exact object key/version/size/SHA를 모두 만족하는 durable identity에 generation을 결합한다. publication/lookup PostgreSQL transaction은 mutable MinIO object를 직접 precheck하지 않고 이 authoritative row를 잠금/조회해 identity를 재검증한다. packet/interface generation 전체와 metadata owner 전환만 atomic publication하며, 실패한 staging generation은 보이지 않는다. canonical source/job 삭제는 source-version row와 해당 source의 READY/STAGING generation 소유권/rows를 같은 transaction에서 삭제하고 기존 object-cleanup outbox를 유지한다. 이 index는 public REST/OpenAPI schema를 추가하지 않고 sync/async export에서 조회되지 않으며 Stage 12 전까지 export-unused다. Stage 9는 LIVE/reanalysis indexing, postings, range reads 또는 그 밖의 Stage 10–12 동작을 포함하지 않는다.

Stage 11 posting generation은 canonical `PCAP_UPLOAD`와 eligible finalized retained `LIVE_SEGMENT` source를 다루며 반드시 READY structural generation을 parent로 가진다. 물리 dimension은 `ALL_PACKET`, `SUPPORTED`, `SRC_ADDRESS`, `DST_ADDRESS`, `SRC_PORT`, `DST_PORT`, `PROTOCOL`, `HAS_PAYLOAD`뿐이고 값에는 packet ordinal만 저장한다. offset/range/content/time/direction/service/sensor/interface는 posting schema에 없다. Generation digest는 source/parent binding document, complete dimension set, schema/parser/filter contract versions, counts, canonical dictionary와 모든 ordinal chunk를 포함한다. source manifest 순서를 따르는 내부 Analysis/Candidate facade는 이 generation들에서 bounded safe-superset ordinal view만 만들며 predicate 재검증을 대체하지 않는다.

Authoritative source-version row와 exact retained object key/backend version/size/SHA는 불변 build identity다. 특히 LIVE upload는 attempt별 immutable generation key를 사용하므로 duplicate-race loser나 과거 cleanup이 이후 같은 이름의 canonical source를 삭제할 수 없다. Canonical source/job 삭제는 posting intent/task/owner/generation/chunk를 source-bound cascade로 제거한다. Structural owner를 교체할 때는 old parent의 posting lifecycle과 child generations를 먼저 structural cascade로 제거해 서로 다른 parent의 metadata가 섞이지 않게 한다. Memory, SQLite, PostgreSQL adapter는 같은 intent/task, staging/publication, lookup/fallback, recovery, cleanup, source deletion 및 structural-replacement 계약을 구현한다.

이 다섯 posting table과 Analysis/Candidate ordinal facade는 모두 internal-only다. Stage 12는 이 ordinal을 기존 structural packet locator와 ephemeral bounded/coalesced range plan으로 변환하지만 locator/range plan을 저장하지 않는다. Public REST/OpenAPI/UI schema, response marker, offset/range read API 또는 새 persistence table/column을 추가하지 않는다. Active sparse path는 full source를 읽지 않고 immutable-version range만 읽으며 dense/unsafe plan은 sequential fallback한다.

Lifecycle row는 접수 즉시 보이지만 artifact metadata는 verified publication을 이긴 terminal compare-and-set에서만 연결한다. Active/cancelled row는 artifact field를 만들지 않는다. Terminal cleanup은 expiry age, retained terminal row count, retained artifact byte total을 각각 독립적으로 제한한다. Staging orphan cleanup은 충분히 오래되고 lifecycle row가 참조하지 않는 attempt object만 삭제한다.

Export 필터는 candidate/internal host IP, time range, port, protocol, direction, sensor와 최대 20개의 include/exclude packet-filter group을 포함한다. Group 내부 조건은 AND, include/exclude group은 각각 OR이며 scalar 조건과 nested 결과는 AND로 결합한다. Source manifest는 provenance별 source ID와 SHA-256을 기록하고 결과 blob은 인증된 download endpoint를 통해 제공한다.

### 2.8 감사·설정·보관

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
- `payload_prefix_hash`, `first_payload_length`, `payload_entropy`,
  `payload_printable_ratio`, `payload_simhash`, `payload_feature_version`
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

후보 상세 응답은 Candidate + Evidence + InternalHost + SensorObservation + AttackTarget + PcapObject availability를 조합한다. Job 목록·상세·상태 전환과 live-job scheduler는 PostgreSQL의 compact metadata만 사용하며 `job_flow_records`를 hydrate하지 않는다. 분석 queue에는 job ID만 전달하고 Worker가 분석 시작 시 payload를 한 번 로드한다. 목록은 PostgreSQL summary를 사용하고 Flow 목록/차트만 ClickHouse를 조회하여 일반 응답 5초 목표를 지킨다. 모든 목록은 cursor 또는 page pagination, allowlisted filter, deterministic sorting을 적용한다.

## 7. 마이그레이션·보관

PostgreSQL은 Alembic, ClickHouse는 순번 migration으로 schema version을 관리한다. 파괴적 변경은 producer/consumer 호환 기간을 둔다. cleanup은 PCAP→Flow→heartbeat/result/audit의 각 정책별 batch job으로 실행하며 삭제량/실패를 감사한다. 결과가 참조하는 PCAP이 만료되면 `EXPIRED`를 즉시 표시한다.
