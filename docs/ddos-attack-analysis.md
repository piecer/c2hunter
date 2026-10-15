# DDoS 공격 트래픽 분석

## Web review and passive exports / 검토 UI와 수동 내보내기

The existing DDoS result screen presents the validated **whole-report verdict** first.
The three independent axes and up to three common patterns are explicitly scoped
to the producer-selected primary target, not presented as a classification of every
finding. Per-axis confidence, unknown authenticity, coverage/drop/clock warnings and
omission counts remain visible. Details are mounted lazily: eight findings per page,
one finding and one candidate at a time. All retained findings remain reachable;
collapse and cached owner replacement remove the old evidence subtree. Stored
v1/v2/v3 reports retain their historical interpretation; missing evaluations are not
fabricated. Facts, deterministic hypotheses and optional AI interpretation stay separate.

A normal-reference picker is available on ordinary DDoS creation, staged PCAP
initiation and DDoS reanalysis. It requests 20 completed jobs per page through the
existing authenticated listing API. Selecting a radio control explicitly asserts
normality; it is not an attack-window recommendation. The server, not the public
summary, determines eligibility and private record/byte limits. Reanalysis defaults
to **keep frozen reference**, including after source deletion. **Clear** sends explicit
`null`; a new selection sends both job and dataset identifiers. C2/network requests
contain no reference fields. Identical retries retain their exact request and idempotency
key; changed intent receives a new key, and pending/retired owners cannot publish a
success into another job.

Explicit download buttons produce at most **65,536 UTF-8 bytes** per file. The
`ddos-review-export-v1` JSON envelope includes report/catalog/job/dataset/finding/
candidate identity, a SHA-256 of the validated report encoded with UTF-8 JSON.stringify
(an identity checksum, not authentication), the complete predicate and both evaluations, public provenance,
coverage qualifiers, approval conditions, exclusions and invalidation guidance.
It never includes private normal-reference rows, credentials or storage paths.
Exports revalidate the current owner and closed report before creating a Blob URL;
every created URL is revoked. JSON is data, not HTML or a command.

`ddos-packet-selection-v1` is a separate context-derived capability. It does **not**
change the frozen v4 producer `supported_export_targets: ["STRUCTURED_JSON"]`.
When exact translation is available, a second download contains a passive `.bpf`
filter with the complete JSON envelope in inert `# ` comments. No server execution,
automatic application, blocking or IDS-rule export exists.

Exact subset: **IPv4 UDP**, uploaded PCAP with a SHA-256 identity, one Ethernet (1)
or raw-IP (101) link type, and at most 32 explicit IPv4 internal networks. Ethernet
translation includes the parser's zero/one/two VLAN-tag cases. Destination address,
source/destination port sets, IPv4 header/fragment/truncation admission and direction
are translated together. Direction is derived from source/destination CIDR membership,
**not** the BPF `inbound` keyword. TCP observation eligibility, length conditions,
protocol-specific fields, IPv6 targets, mixed/unsupported link types and LIVE/unknown
contexts are refused with structured JSON still available. Unsupported fields are
never silently removed. Verify capture SHA-256, link type and network context before
using the filter on that identical offline capture. Filter matches refer to decoded
packets of that capture; evaluation counts describe bounded retained evidence, not
necessarily all captured packets. Neither the filter nor a match proves maliciousness.

Verification includes actual Chromium desktop/mobile ko/en UI, exact downloaded JSON
and BPF bytes, native libpcap/tcpdump offline selection versus independent predicate
replay, and browser-produced payloads through real ASGI/SQLite admission, preparation,
worker and readback. Browser HTTP fixtures and the explicit offline queue are not
claims of deployed PostgreSQL, physical sensor or LIVE acceptance.

## v4: 평가한 방어 시그니처 후보

현재 새 분석은 `ddos-attack-report-v4` / `ddos-taxonomy-v4`를 생성한다.
v1/v2/v3 저장 보고서는 해당 계약 그대로 읽으며 다시 해석하지 않는다.
v3의 보수적인 3축 분류는 변경하지 않는다. 새 `signature_candidates[].evaluation`은
실제로 실행한 AND predicate, 공격 데이터의 평가 결과, 별도 정상 참조의 결과를 담는다.
기존 pattern support histogram은 rule 일치율이 아니다.

- 대상 IP는 destination, 방향은 관찰된 INBOUND/OUTBOUND, protocol/port/flags를
  명시한다. 포트의 `null`은 명시적 무제약이다. 관측 누락은 wildcard가 아니다.
- flag conjunction은 완전한 단일 packet 관측에서만 평가한다. 집계 flag 카운터를
  packet별 conjunction으로 바꾸지 않는다. 판정은 match/nonmatch/unknown 3값이다.
- 길이 조건은 `CAPTURED_FRAME_BYTES`, `IP_BYTES`, `TRANSPORT_PAYLOAD_BYTES`를
  구별한다. 현재 생산 후보는 길이를 제한하지 않는다. matcher는 완전한 단일 packet의
  frame/payload 관측만 사용하며 관측되지 않은 IP 길이는 UNKNOWN이다.
  protocol field는 단일 packet의 ICMP type만 지원한다. payload/hash로 bytes를 복원하지 않는다.
- `matched/eligible/unknown_records`와 `matched/eligible/unknown_packets`는 별도다.
  비율은 각각 matched/eligible이며 분모가 0이면 null이다. 집계 tuple만으로 확인되는
  predicate에는 그 record의 packet 수를 사용할 수 있지만 flag/길이는 UNKNOWN이다.
- 공격 근거는 canonical JSON 순서의 최대 512 records, 256 KiB 완전 prefix이다.
  순서 변경에도 동일한 표본을 선택한다. 누락 record 수, 실제 bytes, 한도, sample digest와
  최대 8개의 `canonical-index:record-sha256` 근거 참조를 보존한다. 시간/sensor ID도
  근거 digest에 포함한다. 무작위 표본이나 전체 packet coverage라는 주장은 하지 않는다.
- 후보 confidence는 분류 confidence와 별개로 항상 low이며 보정된 공격 확률이 아니다.
  정상 공용 서비스 제외, 대상 소유권 확인, 정상 트래픽 검토, 운영자 승인이 필요하다.
  데이터셋/토폴로지 변경 시와 매 사용 전에 재검증한다. 자동 적용은 없다.
  v4 생산자의 표현 목표는 `STRUCTURED_JSON`이다. Web의 별도 버전 검토용 다운로드와
  문맥 기반 수동 filter는 위의 Web review 절을 따른다.
- evaluation별 8192 bytes, 모든 공개 signature 배열 합계 1 MiB를 초과하면 부분 성공을
  반환하지 않고 분석 실패로 처리한다. 기존 finding/record 한도는 유지한다.

### 운영자가 별도 정상 참조 선택

`POST /api/v1/analysis-jobs`, `POST /api/v1/pcap-analysis-jobs/initiate` 및
`POST /api/v1/analysis-jobs/{id}/reanalyze`에 다음 선택을 명시한다:

```json
{"ddos_normal_reference":{"job_id":"existing-job-id","dataset_id":"its-dataset-id"}}
```

기존 단일 binary PCAP 업로드는 query의 `ddos_normal_reference_job_id`와
`ddos_normal_reference_dataset_id`를 함께 사용한다. C2 요청은 이 필드를 허용하지 않는다.
재분석에서 생략하면 부모의 저장된 snapshot을 상속하고 명시적 null이면 해제한다.
같은 idempotency key에 다른 참조를 지정하면 409이며 기존 작업을 수정하지 않는다.

기존 global job RBAC(분석 생성 ANALYST, 조회 VIEWER)를 그대로 사용한다. 새로운
per-user tenant 소유권 모델이나 C2 baseline 승인 권한을 도입하지 않는다. 선택한 job과
그 job의 dataset ID가 일치하고 COMPLETED 상태여야 한다. 부분/손실 capture,
미완료/없는 job, 잘못된 dataset, 같은 분석 dataset, 과도한 입력은 명시적으로 거절한다.
SQL은 raw flow body를 가져오기 전에 최대 512 records / 1 MiB source bytes를 검사한다.
메모리 adapter는 전체 flow deepcopy 없이 제한된 필드만 취득한다. 서버 측 SQL 길이
preflight 비용 자체가 상수 시간이라는 주장은 하지 않는다.

선택 시점에 최대 256 KiB matcher 근거 projection, content digest, job/dataset identity,
선택자와 선택 시각을 작업 metadata에 영속 저장한다. 별도 request binding을 worker에서
검증하며, queue에는 ID/lease만 전달해도 실제 PostgresJobLoader가 저장 snapshot을 읽는다.
원본 변경/삭제 및 재시작 이후에도 저장 snapshot만 비교한다. 삭제된 원본의 재선택은 실패한다.
원본 job의 전체 raw payload가 아니라 matcher projection의 content identity이다.

정상성은 운영자의 선택이지 분석기의 인증이 아니다. 참조 결과는 항상 retained-evidence
coverage limited이며 전체 정상 트래픽의 오탐률로 일반화하지 않는다. 정상 참조가 없으면
`UNMEASURED`, result/reference는 null이며 오탐 0으로 표시하지 않는다. 참조가 있어도
UNKNOWN 근거는 eligible 분모에서 제외하고 분모 0이면 rate는 null이다. private snapshot은
일반 job get/list와 AI 입력에 노출되지 않는다. AI는 bounded predicate/result/provenance만 받는다.

### v4 integrity and retry boundaries

- Every v4 report carries required `normal_reference`: the approved bounded public
  provenance object, or explicit `null`. It is present even with zero findings.
  Each candidate must agree with it. Result ingestion compares it with the persisted
  job's independently bound snapshot before completion/ACK; missing or foreign
  provenance fails `INVALID_DDOS_RESULT`. Legacy v1–v3 do not acquire this field.
- API and saved-report AI admission share finding/report context checks. Ordinary
  predicates bind destination IP, role/direction, protocol and destination port;
  MULTI_VECTOR retains component predicates. Spoofing heuristics may omit flags and
  source ports, not change the finding's destination. AI validates before truncation.
- Every eligible nonmatching record has positive packet weight. Record and packet
  complements are zero together. The global attack sample's sampled + omitted
  records equal `summary.evaluated_records`; sampled packets cannot exceed report
  packets and equal them without omissions. Candidates share the same global sample
  digest, byte count and totals; this is not a per-finding population denominator.
  Evidence indices use canonical decimal spelling (`0`, `1`, …), never `00`.
- Known parser skips, sensor drops, discarded packets and interrupted captures reject
  reference admission across C2/DDoS modules and inherited dataset quality. Scalar
  SQL preflight does not hydrate source/capture JSON bodies. Missing legacy quality
  facts remain unknown, not a fabricated zero; `coverage_limited` stays true.
- Staged uploads compare the computed capture digest with the selected normal dataset
  before capture publication. Preparation rechecks the derived dataset binding before
  queueing, including resumed preparation. Distinct captures remain allowed.
- New DDoS requests persist a private normalized request commitment. Ordinary creation,
  staged initiation, binary upload and reanalysis resolve matching idempotency winners
  before reacquiring a live normal source. Exact replay uses the frozen snapshot after
  source deletion/mutation; a different reference or payload returns 409. The existing
  atomic repository winner still arbitrates concurrent creates. This does not make a
  new request selecting a deleted source admissible.
- `ddos_reference_snapshot`, `ddos_reference_binding`, and `ddos_request_binding` are
  private job metadata, excluded from ordinary create/get/list/reanalysis/cancel/replay
  responses and AI input. Public `normal_reference` is provenance, not the private
  integrity commitment or retained records. No model calls or enforcement are implied.

## 목적

`ddos_attack`은 C2Hunter의 독립 분석 도메인이다. 관찰된 TCP/UDP/ICMP 트래픽에서 DDoS 형태를 분류하고, 보호 대상 또는 내부 참여 호스트 관점의 역할, 방어 대상 자원에 대한 목적 가설, 운영자 승인이 필요한 대응 항목을 생성한다.

이 결과는 공격자 귀속, 서비스 장애 입증, source spoofing 확인 또는 자동 차단 명령이 아니다. 기존 C2 Candidate/TI/MISP/AI 자동화로 전달되지 않는다.

## 지원 유형

- `TCP_SYN_FLOOD`: SYN-only 비율이 지배적인 분산 TCP 트래픽
- `TCP_ACK_FLOOD`: ACK-only 비율이 지배적인 분산 TCP 트래픽
- `TCP_RST_FLOOD`: RST 비율이 지배적인 분산 TCP 트래픽
- `UDP_FLOOD`: 반사 형태로 한정되지 않는 분산 UDP 트래픽
- `ICMP_ECHO_FLOOD`: packet-level ICMP type이 있는 echo request 중심 트래픽
- `ICMP_FLOOD`: type metadata가 없거나 echo 중심이 아닌 ICMP 트래픽
- `POSSIBLE_REFLECTION_AMPLIFICATION`: v3에서는 DNS/NTP 응답 의미가 관찰되고 일치하는 요청으로 설명되지 않는 victim-side UDP 형태 (반사 의심, 증폭 실측 아님)
- `MULTI_VECTOR`: 같은 target에 겹쳐 관찰된 복수 flood 유형

HTTP request flood와 TLS handshake flood는 현재 Flow 계약에 필요한 L7 요청 의미가 없어 분류하지 않는다.

## 판정과 목적

Report verdict는 `attack_likely`, `suspicious_traffic`, `no_clear_attack`, `insufficient_evidence` 중 하나다. 개별 positive finding의 likelihood는 `LIKELY` 또는 `POSSIBLE`이다. 지원되는 형태가 없을 때 coverage가 완전하면 `no_clear_attack`, 불완전하면 `insufficient_evidence`를 사용하며 finding에 `NOT_OBSERVED` 또는 `INSUFFICIENT_EVIDENCE`를 넣지 않는다. 절대 traffic floor, 관찰 source 분산, protocol/flag 형태, 적격 baseline을 함께 사용한다. baseline 또는 TCP reverse-response 가시성이 없으면 SYN positive finding은 최대 `POSSIBLE`이다. source 수가 부족한 고용량 traffic은 `DOS_LIKE_TRAFFIC` warning을 내고 DDoS로 확정하지 않는다.

목적은 공격자의 동기가 아니라 방어 관점의 자원 고갈 가설이다.

- SYN flood: connection-state exhaustion
- ACK/RST 또는 작은 packet 중심 flood: packet-processing exhaustion
- UDP/ICMP: bandwidth 또는 packet-processing exhaustion
- reflection 형태: reflected bandwidth exhaustion
- multi-vector: multi-resource exhaustion

## 측정 정밀도

- `PACKET`: `packet_evidence_complete=true`, `packet_count=1`. 1초 bucket peak를 계산할 수 있다.
- `AGGREGATED_FLOW`: sensor 집계 Flow. target의 최초 시작부터 최종 flow 종료까지의 구간에 대해 합산 packet/byte 평균률을 계산하며 가상의 packet timestamp나 peak를 만들지 않는다.
- `MIXED`: packet과 aggregate가 함께 있을 때 packet subset peak는 하한으로 표시한다.

Sensor 집계 TCP Flow는 `transport_payload_packet_count`로 payload가 있었던 packet 수를
명시한다. 이 값이 없는 이전 Sensor record에서도 ACK-dominant 형태는 숨기지 않지만
`TCP_PAYLOAD_VISIBILITY_UNKNOWN`으로 payload 관측 한계를 표시하고 likelihood를
`POSSIBLE`로 제한한다.

동일 packet의 multi-sensor mirror dedup을 입증할 fingerprint가 없으면 source/sensor 합산이 중복될 수 있으므로 `DUPLICATE_CAPTURE_NOT_EXCLUDED` warning을 표시한다.

Controller는 분석기 실행 전에 수집 범위 정보를 함께 snapshot한다. 업로드 PCAP에서 parser가
packet을 제외했으면 `PARSER_SKIPPED_PACKETS`, capture limit 또는 중단으로 데이터셋이
부분적이면 `PARTIAL_CAPTURE`를 표시한다. Sensor 작업에 job-scoped drop/clock telemetry가
없으면 현재 heartbeat의 누적 수치를 해당 작업에 잘못 귀속하지 않고
`SENSOR_CAPTURE_QUALITY_UNAVAILABLE`로 표시한다. 이들 coverage qualifier가 있으면
`no_clear_attack`과 high-confidence 판정을 금지한다.

## 기본 threshold

| Parameter | Default |
|---|---:|
| `ddos_bucket_seconds` | 1 |
| `ddos_min_duration_seconds` | 3 |
| `ddos_min_source_count` | 20 |
| `ddos_min_packet_count` | 1,000 |
| `ddos_min_packets_per_second` | 100 |
| `ddos_min_bits_per_second` | 1,000,000 |
| `ddos_baseline_min_buckets` | 20 |
| `ddos_baseline_ratio` | 5.0 |
| `ddos_mad_z_threshold` | 6.0 |
| `ddos_protocol_share_threshold` | 0.80 |
| `ddos_tcp_flag_share_threshold` | 0.80 |
| `ddos_response_ratio_max` | 0.20 |
| `ddos_reflection_port_share_threshold` | 0.60 |
| `ddos_reflection_min_average_packet_bytes` | 256 |
| `ddos_overlap_window_seconds` | 10 |

Reflection source-port catalog v1은 17, 19, 53, 123, 389, 1900, 11211이다. source port만으로 amplification을 확정하지 않으며 request/response 증폭비를 관찰하지 못하면 `amplification_ratio=null`을 유지한다.

## 안전한 대응 출력

대응은 닫힌 code catalog와 `requires_human_approval=true`로 제공한다. 유형별 조치가 먼저 오고, 증거 보존·영향 실측·upstream 연락·복구 및 오탐 모니터링이 뒤따른다. UI는 ko/en local registry로 번역하며 unknown code는 raw text를 반사하지 않고 보고서 전체를 fail closed한다.

RTBH/FlowSpec/scrubbing은 upstream 승인과 영향 검토가 필요하다. ICMP 전체 차단은 PMTUD를 손상할 수 있어 권고하지 않는다. 이 모듈은 방화벽, router, WAF 또는 cloud API를 호출하지 않는다.

## Bounds와 coverage

- 전체 입력 record: 2,000,000
- 유효 target record가 100개 미만이면 `SAMPLE_WINDOW_SHORT`로 표시하고 finding confidence를 낮춘다. 관측된 positive finding은 보존한다.
- target state: 4,096
- target당 packet bucket: 3,600
- published finding: 100
- finding당 evidence/uncertainty/recommendation code: 8

limit+1에서 warning, `counts_are_lower_bounds=true`, `coverage_complete=false`를 기록하고 `no_clear_attack`을 금지한다. 작업 목록은 compact `ddos_attack_summary`만 반환한다. full `ddos_attack` report는 작업 상세 및 inline/PCAP 생성 응답에서 제공한다.

## 실행 예

PCAP upload:

```text
POST /api/v1/pcap-analysis-jobs?name=case&filename=capture.pcap&analysis_module=ddos_attack
Content-Type: application/vnd.tcpdump.pcap
```

Live/Historical job은 기존 `/api/v1/analysis-jobs` envelope에서 `analysis.module`을 `ddos_attack`으로 설정한다. 재분석은 원 dataset과 snapshot을 재사용하며 DDoS threshold만 선택적으로 override할 수 있다. C2 detector weight는 DDoS 재분석에서 거부한다.

## 검증

```text
.venv/bin/pytest -q analysis/tests/test_ddos_attack.py controller/tests/test_ddos_attack_api.py
npm --prefix web run test:unit -- DDoSAttack.test.tsx
make test
make lint
make build
make test-coverage
make benchmark-ddos-analysis
```

Benchmark는 양의 bounded record 수, 3회 실행 시간, source revision, runtime/host 정보, 실제 analyzer 상수와 effective threshold를 JSON/Markdown artifact에 기록한다.

완료 판정에는 실제 Controller, compatible worker, Web UI와 bounded LIVE sensor 경로가 필요하다. fixture 또는 inline POC만으로 production path를 입증하지 않는다.


## v3 independent evidence axes / 독립 근거 축

New results use `ddos-attack-report-v3` with `ddos-taxonomy-v3`. Saved v1/v2
reports retain their historical semantics and closed validators; they are not
rewritten or relabelled. Unknown versions and malformed-present metadata fail
closed. Classification adds `evidence` and `axes` to the four historical keys.
Each axis contains `confidence`, `supporting_codes`, `counter_codes`, and
`unknown_codes`; the backend and Web derive the exact labels/reasons from the
bounded evidence. Confidence is qualitative support, not an attack probability.

- Delivery: `UNKNOWN`, `DIRECT_DISTRIBUTED`, `REFLECTION_AMPLIFICATION`, or
  `MIXED`. Reflection means **suspicion**, never measured amplification. Port and
  average size alone do not select a reflection finding. The historical
  `ddos_reflection_min_average_packet_bytes` setting remains accepted for saved
  policy compatibility but is not a v3 response-semantic gate.
- Population: `DISTRIBUTED_UNATTRIBUTED`, `REFLECTOR_SET`,
  `BOTNET_LIKE_COORDINATION`, or component-level `MIXED`. Role and source count
  alone are insufficient. Coordination requires at least three sources sharing
  the same protocol, TCP flags, IP length, and first-64-payload-byte SHA256
  profile in at least three common one-second buckets within a fixed ten-second
  Unix epoch window. Each supporting source therefore contributes at least
  three real packet times, spanning at least two bucket starts. Eligible,
  coordinated and observed source counts, sample counts, shared buckets and
  window width remain distinct denominators. Responses from reflectors do not
  establish compromised-client coordination. Legitimate coordinated activity
  remains possible; compromise/actor attribution are unconfirmed.
- Authenticity: valid-looking addresses remain `SPOOFING_UNCONFIRMED` without
  independent source validation. Only an actually observed multicast
  source address supports `SPOOFING_SUSPECTED`; this is invalid
  addressing evidence, not universal spoofing detection. Unspecified source
  addresses have protocol-specific legitimate uses and remain unconfirmed. Random IP-ID,
  nonmonotonic IDs and TTL diversity remain qualified observations and do not
  produce either suspicion or `SOURCE_CONSISTENT`. No new trusted-spoofing flag
  or fabricated transport-authentication evidence is introduced.

### Real producer metadata

`ddos_packet_evidence` is optional (`null` from legacy model serialization means
absent) with exact keys `version: 1`, `samples`, `omitted_samples`. Each sample
has a signed safe integer `timestamp_us` (−(2^53−1) through 2^53−1), a SHA256 `profile`, closed `semantic` and
nullable SHA256 `transaction`. Semantics are `OTHER`, `UNKNOWN`,
`DNS_REQUEST`, `DNS_RESPONSE`, `NTP_REQUEST`, `NTP_RESPONSE`.

PCAP network-evidence opt-in and the LIVE packet decoder produce actual samples;
aggregate start/end timestamps are never expanded into packet times. The LIVE
transport serializes the sidecar through FlowBatch records; ingress, immutable
job snapshots and workers preserve it. C2 projections discard the sidecar,
including explicit-null defaults, and do not activate another analysis domain.
PCAP defaults without network evidence are unchanged.

Epoch conversion uses integer datetime differences, not floating-point Unix
seconds. Pre-epoch PCAPNG interface offsets retain their negative timestamps.
Complete packets outside the sample safe-integer range count as omitted samples;
the original packet counts and flow timing remain admissible and unchanged.
For nanosecond-origin LIVE data, samples floor to microseconds while datetime
loses the start's nanosecond remainder. If that start is `S+r` microseconds
(`S` integral, `0 <= r < 1`) and wire duration is `D` microseconds, sample
admission uses `[S, S+ceil(D)]`: `floor(S+r+D) <= S+ceil(D)`. The upper
allowance relative to `S+D` is strictly below one microsecond, and zero for
integral-microsecond durations. Ingress and analysis share this conversion;
negative samples, historical microseconds and rollover do not use a float epoch.
This bound does not rewrite legacy start/duration or permit earlier samples.

DNS parsing is deliberately bounded to standard-query headers and one
uncompressed question (up to 128 label steps, with a bounded name offset).
It identifies response **headers**, not complete answer validity, DNSSEC, or
source authenticity. Compression, other opcodes and truncated headers abstain.
NTP parsing accepts complete 48-byte-or-longer v3/v4 client/server headers;
server mode 4 requires stratum 1–15. Other modes, including control/private-mode
amplifiers, abstain rather than infer responses from port 123. UNKNOWN samples
remain counted but cannot support affirmative non-reflector coordination.
Replies from unsupported reflection-service ports 17, 19, 389, 1900 and 11211
also abstain; no new application parser or port-only reflection claim is implied.
OTHER direct packets and parsed DNS/NTP requests remain coordination-eligible.

Matching requests use the same sensor, reversed endpoint tuple, bounded
transaction token, and a preceding packet time within ten seconds. DNS tokens
bind ID and question; NTP tokens bind request transmit/response origin fields
(nonzero only). This is counterevidence, not authenticated one-to-one transaction
accounting. Missing requests can reflect capture position or retention limits:
absence is not proof. Amplification remains `null`. Observed reflector addresses
are distinct from the upstream victim-IP spoofing hypothesis. Known omitted or
unobserved request-direction samples qualify the dependent reverse-response
assessment as coverage-limited, lowering axis confidence. They do not count as
response omissions, prove benign traffic, or erase unmatched observed responses.
A single analysis-wide set retains at most 4,096 loss scopes (sensor, client IP/
port, server IP/port). Loss is conservative over the analysis interval; exceeding
the set bound marks all parsed-response assessments coverage-limited without
adding more keys. Matching still shares a sensor observation domain across
capture interfaces; cross-interface identity is not established.

Both v3 report consumers require `response_samples > matched_response_samples`
for `POSSIBLE_REFLECTION_AMPLIFICATION`, in addition to closed counter and
finding denominators. Non-MULTI_VECTOR findings require `component_count = 0`.
These are v3-only invariants; frozen v1/v2 interpretation is unchanged.

### Independent evidence-state budgets

| Scope | Maximum retained packet samples |
|---|---:|
| One LIVE flow / wire bundle | 16 |
| One source (LIVE capture; analyzer per target/source) | 32 |
| One target | 2,048 |
| One analyzer invocation / LIVE capture aggregator lifetime | 32,768 |

LIVE admission maps acquire keys only with admitted samples; flush does not
replenish the lifetime quota. Samples outside the original flow interval are
omitted rather than rewriting legacy flow time semantics. Exact limits retain
samples; limit+1 counts omissions. The analyzer additionally reports packets
without sample evidence separately from omitted samples. No unbounded
source-by-bucket matrix is retained. Sample omission, missing packet evidence,
parser/drop/clock/partial/mirror qualifiers suppress coordinated-population
claims and lower axis confidence. These sample-specific bounds are separate
from the report's existing whole-record coverage counters.

The AI projection preserves the v3 axes under `ddos-ai-input-v3`, retains at
most 20 findings within its unchanged 48 KiB byte budget, and counts additional
omitted findings. Existing detailed UI exposes ko/en reasons and bounded support
counts; candidate matching improvements and presentation/export redesign are
not part of this version.
