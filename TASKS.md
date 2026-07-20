# C2Hunter MVP 작업 및 요구사항 추적표

> 기준 명세: `SPEC.md` (2026-07-20). 이 문서는 개발/검증 에이전트의 작업 권위 목록이다. `SPEC.md`는 수정하지 않는다.

## 0. 사용 규칙

### 상태

- `[ ] PLANNED`: 미착수
- `[-] IN_PROGRESS`: 진행 중(동시에 담당자 명시)
- `[x] DONE`: 완료 조건과 연결된 테스트/산출물이 실제 통과
- `[!] BLOCKED`: 원인·재현·후속 작업 기록

현재 모든 구현 작업은 **PLANNED**다. 문서 작성만 완료됐으며 프로덕션 구현 완료로 간주하지 않는다.

### 작업 갱신 규칙

1. 각 작업은 요구사항 ID(`REQ-*`), Phase, 의존성, 완료 조건을 가진다.
2. 구현 전에 실패 테스트를 만들고, 단위 테스트→lint/정적 분석→관련 통합→전체 회귀 순서로 검증한다.
3. 실패 테스트를 비활성화하거나 assertion을 약화하지 않는다. placeholder/TODO/FIXME/mock 반환은 완료가 아니다.
4. 공개 API/protobuf 변경 시 OpenAPI/proto 문서와 계약 테스트를 함께 갱신한다.
5. Phase gate가 실패하면 다음 Phase로 넘어가지 않는다.
6. 완료 시 명령, 결과, coverage/benchmark artifact 경로를 해당 작업 비고에 기록한다.
7. 사소한 선택은 기본 기술 스택을 따르고 중요한 변경은 ADR로 남긴다.

## 1. 요구사항 ID 레지스터

아래 ID는 명세의 모든 규범적 영역을 추적 가능한 단위로 묶는다. 세부 bullet은 해당 ID의 완료 조건에서 모두 검증한다.

| 요구사항 ID | SPEC | 요구사항 범위 |
|---|---|---|
| REQ-SCP-001 | §2, §3.1 | 2+ Linux 센서, 중앙 분석, Web/REST, 후보·점수·근거·단말·시계열·PCAP, 1M+ packet, 자동 테스트, Compose |
| REQ-SCP-002 | §3.2, §18.4 | TLS 복호화/능동 스캔·C2 접속·제어·공격 재현/치료/ML/K8s/초고속·장기 cluster 제외 및 방어 목적 제한 |
| REQ-ARC-001 | §4, §5, §24 | Sensor/API/Worker/metadata/flow/object/UI/queue 경계, 권장 기술/저장소 구조, 버전 pin/lock |
| REQ-ARC-002 | §4.2 | 센서 outbound mTLS gRPC 연결, NAT/방화벽 내부 지원, Controller inbound 의존 금지 |
| REQ-DIR-001 | §6.1 | capture source별 `INBOUND/OUTBOUND/BIDIRECTIONAL/UNKNOWN` 설정 |
| REQ-DIR-002 | §6.2 | interface/VLAN/internal CIDR/BPF rule 기반 판별, 불명확 시 `UNKNOWN`(추측 금지) |
| REQ-DIR-003 | §6.3 | 사설·공인 대역을 포함한 configurable internal networks |
| REQ-SEN-001 | §7.1 | 고유 Sensor ID 및 등록 필드 전체(이름/host/version/OS/kernel/interface/MAC/direction/capability/time/disk/drop) |
| REQ-SEN-002 | §7.2 | 기본 10초 heartbeat, 자원/capture/rx/drop/queue/error 정보, 5개 sensor 상태 |
| REQ-SEN-003 | §7.3 | 시작·종료/기간/packet/byte/user stop/disk/timeout 종료, earliest-condition 우선 |
| REQ-SEN-004 | §7.4 | BPF, src/dst CIDR/port, TCP/UDP/ICMP, IP version, direction, payload/PCAP 필터 |
| REQ-SEN-005 | §7.5 | 명세 Flow key/필드 전체, configurable 60초 idle timeout |
| REQ-SEN-006 | §7.6 | DNS/HTTP/TLS/unknown protocol metadata 전체, body/payload 기본 미저장 |
| REQ-SEN-007 | §7.7, §19.2 | file spool, reconnect resend, batch dedup, size/age/disk/loss; backpressure 순서와 손실 보고 |
| REQ-CTL-001 | §8.1–8.2 | sensor 목록/상세/enable/tag/group/interface/direction/heartbeat/error/drop, 그룹·개별 분석 선택 |
| REQ-CTL-002 | §8.3 | 10개 job 상태, 허용 전이, 시각·원인 audit, 부분 완료 |
| REQ-CTL-003 | §8.4 | analysis 생성 `idempotency_key`, 중복 생성 금지 |
| REQ-TRG-001 | §9.1–9.2 | 분석 요청 조건 전체와 예시 구조 검증 |
| REQ-TRG-002 | §9.3 | 저장 시간 범위 과거 분석과 파라미터 변경 재분석 |
| REQ-DET-001 | §10 본문 | 독립 detector 공통 인터페이스와 versioned Evidence |
| REQ-DET-002 | §10.1 | 다수 host 공통 목적지 지표/threshold 및 DNS/NTP/CDN/cloud/allowlist 억제 |
| REQ-DET-003 | §10.2 | beacon inter-arrival/mean/std/CV/count/autocorrelation/jitter/size, ±10–30% jitter, multi-host/sensor |
| REQ-DET-004 | §10.3 | configurable synchronization window(기본 2초)와 반복 동기화 점수 |
| REQ-DET-005 | §10.4 | 작은 inbound command 후 1–30초 outbound 증가, baseline/PPS/공통 target·port·protocol·size/multi-sensor |
| REQ-DET-006 | §10.5 | 저용량 장기 지속·소수 packet·작은 크기·목적지 안정성/희귀성 |
| REQ-DET-007 | §10.6 | port/TLS/cert/HTTP/DNS/TXT/payload hash/size sequence/ratio 유사성, 원문 대신 hash/statistics |
| REQ-DET-008 | §10.7 | 복수 센서 공통 context key와 기본 ±2초 clock tolerance |
| REQ-DET-009 | §10.8 | packet dedup 필드 전체, logical count 제거 후 sensor observations 보존 |
| REQ-SCR-001 | §11 | 7개 양의 항목 최대 20/15/15/25/10/10/5, 합계 0–100 |
| REQ-SCR-002 | §11 | allowlist 제외 및 공용/업무/단일 host/표본 부족 감점 상한 |
| REQ-SCR-003 | §11 | LOW/MEDIUM/HIGH/CRITICAL 경계와 반드시 제공되는 산출 근거 |
| REQ-RES-001 | §12 | Candidate JSON 필드 전체(시간/protocol/port/host/sensor/evidence/pcap/target/FP note) |
| REQ-RES-002 | §12.1 | host/sensor/time/detector/input metric/score-confidence/FP/PCAP 설명 가능성 |
| REQ-UI-001 | §13.1 | dashboard 6개 지표/차트 |
| REQ-UI-002 | §13.2 | sensor 화면 상태/heartbeat/interface/direction/version/resource/capture/error |
| REQ-UI-003 | §13.3–13.4 | 분석 생성 입력 전체, 진행률/count/time/sensor/cancel/error·warning |
| REQ-UI-004 | §13.5 | 후보 목록 필드와 상세 chart/host/sensor/beacon/timeline/target/evidence/flow/PCAP |
| REQ-UI-005 | §13.6 | 5종 allowlist+설명/만료 CRUD 및 제외 통계 |
| REQ-PCP-001 | §14.1 | 작업별 PCAP opt-in, size/time/job end/restart 회전, 기본 1GB/5분 |
| REQ-PCP-002 | §14.2 | 전체/후보 PCAP, 7종 필터, 대형 export 비동기 |
| REQ-PCP-003 | §14.3 | 인증/RBAC/audit/expiring URL/path·filename 방어/max size/access check |
| REQ-API-001 | §15 | `/api/v1`에 명세의 20개 REST endpoint, OpenAPI |
| REQ-API-002 | §15 | 모든 목록 pagination/filtering/sorting |
| REQ-RET-001 | §16 | configurable retention: PCAP7/Flow30/result180/audit365/heartbeat30일, cleanup |
| REQ-RET-002 | §16 | 참조 PCAP 삭제를 결과/UI에 명시 |
| REQ-TIM-001 | §17 | NTP/PTP 운영, 권장 100ms, 허용 2초, heartbeat offset, DEGRADED/warning |
| REQ-SEC-001 | §18.1 | mTLS/HTTPS, secret 평문 금지, cert expiry/revocation, input validation |
| REQ-SEC-002 | §18.2 | ADMIN/ANALYST/VIEWER/SENSOR RBAC와 권한 범위 |
| REQ-SEC-003 | §18.3 | 8종 audit event와 user/time/IP/action/target/result |
| REQ-PER-001 | §19.1 | 1M+ OOM 없음, no full-load, chunk/streaming, 180초 목표, RSS<8GB 목표/기준 |
| REQ-PER-002 | §19.1 | Sensor 100k PPS/drop≤1% 목표, Flow API≤5초, restart recovery |
| REQ-ERR-001 | §20 | 구조화 error envelope/code와 명세 10개 오류 |
| REQ-ERR-002 | §20 | 일부 sensor 실패 시 가능한 분석 및 `PARTIALLY_COMPLETED`/손실 표시 |
| REQ-OBS-001 | §21.1 | JSON log와 9개 필수 필드 |
| REQ-OBS-002 | §21.2 | Prometheus `/metrics`와 명세 10개 metric |
| REQ-OBS-003 | §21.3 | `/health` liveness, `/ready` DB/queue/storage readiness |
| REQ-TST-001 | §22.1 | 명세 14개 단위 대상 및 detector별 독립 테스트 |
| REQ-TST-002 | §22.2 | 고정 seed 합성 traffic generator와 Scenario A–G oracle 전체 |
| REQ-TST-003 | §22.3 | Compose 12단계 통합 흐름 |
| REQ-TST-004 | §22.4 | Playwright 9개 E2E 사용자 흐름 |
| REQ-TST-005 | §22.5 | `benchmark-1m`, 1M 생성→전체 pipeline, time/RSS, JSON/MD artifact |
| REQ-TST-006 | §22.6 | Controller/Redis/Worker/Sensor network/MinIO/Postgres/batch redelivery 복구 테스트 |
| REQ-TST-007 | §23 | backend 80%, detector 90%, sensor core 80%, API 정상/오류, offline/reproducible/safe fixtures |
| REQ-DEV-001 | §25–26 | Phase 작업, 반복 절차, 실패 처리, config/secret/no placeholder/no fake/streaming/retry/API docs 원칙 |
| REQ-CMD-001 | §27 | 명세에 열거된 12개 필수 Make target과 `make test` 범위, CI 실행 순서 |
| REQ-CI-001 | §28 | PR/push CI: Go/Python/TS lint, unit/integration/coverage/image/security/secret scan |
| REQ-DOC-001 | §29 | README 11개 주제와 운영 문서 9개 주제, 실제 구현 일치 |
| REQ-DOD-001 | §30 | 최종 Definition of Done 24개 항목 전체 |
| REQ-VAL-001 | §31 | 최종 10개 명령 순서, 8개 런타임 확인, 실패 시 처음부터 재실행 |
| REQ-RPT-001 | §32 | `IMPLEMENTATION_REPORT.md` 11개 section과 미완료 보고 필드 |

## 2. 현실적인 MVP 수직 슬라이스 순서

Phase는 기능 계층별 일괄 구현이 아니라 매 단계 실행 가능한 end-to-end 경로를 만든다.

### Phase 0 — 계약·재현 가능한 골격

| 상태 | 작업 ID | 작업 | 요구사항 | 의존성 | 완료 조건 |
|---|---|---|---|---|---|
| [ ] | P0-001 | monorepo 디렉터리, pinned Go/Python/Node 의존성/lock, 환경 설정 계약 생성 | REQ-ARC-001, REQ-DEV-001 | 없음 | 명세 구조 존재, secret 없는 `.env.example`, lock 3종, config validation test 통과 |
| [ ] | P0-002 | Compose에 PostgreSQL/Redis/ClickHouse/MinIO/API/Worker/Web/Sensor A/B healthcheck 구성 | REQ-SCP-001, REQ-ARC-001 | P0-001 | `docker compose config`, `make up`, 모든 infrastructure health |
| [ ] | P0-003 | Makefile의 필수 13 target과 CI skeleton 작성 | REQ-CMD-001, REQ-CI-001 | P0-001 | `make help`에서 target 노출, dry contract test, CI 순서 lint→unit→integration→build→security |
| [ ] | P0-004 | 공통 JSON logging, request/job/sensor correlation, error envelope 구현 | REQ-ERR-001, REQ-OBS-001 | P0-001 | 필수 log 필드와 구조화 API 오류 계약 테스트 |
| [ ] | P0-005 | health/ready/metrics와 dependency probe 구현 | REQ-API-001, REQ-OBS-002, REQ-OBS-003 | P0-002,P0-004 | `/health`, dependency별 `/ready`, Prometheus metric 계약 테스트 |
| [ ] | P0-006 | protobuf/API/domain/schema v1 계약과 migration harness 작성 | REQ-ARC-002, REQ-API-001 | P0-001 | proto lint/compat, Alembic/CH migration up, OpenAPI snapshot 통과 |

**Gate 0:** `docker compose up -d`와 `make test` 성공(명세 Phase 1 완료 조건). 이 시점 `make test`는 존재하는 unit+핵심 smoke integration을 실제 실행해야 한다.

### Phase 1 — 첫 수직 슬라이스: offline packet → Flow → 단일 후보 API

| 상태 | 작업 ID | 작업 | 요구사항 | 의존성 | 완료 조건 |
|---|---|---|---|---|---|
| [ ] | P1-001 | 방향/internal CIDR classifier를 TDD로 구현 | REQ-DIR-001, REQ-DIR-002, REQ-DIR-003, REQ-TST-001 | P0-006 | 4 enum, interface/VLAN/CIDR/rule, 불명확 UNKNOWN, public CIDR test |
| [ ] | P1-002 | offline/libpcap capture adapter와 packet filter 구현 | REQ-SEN-003, REQ-SEN-004 | P1-001 | 시간/기간/packet/byte/stop earliest 종료 및 모든 filter 단위 테스트 |
| [ ] | P1-003 | Flow key/aggregation/timeout/statistics를 bounded memory로 구현 | REQ-SEN-005, REQ-PER-001, REQ-TST-001 | P1-002 | 모든 필드, 60초/config timeout, chunk test, sensor core coverage 기반 |
| [ ] | P1-004 | DNS/HTTP/TLS/unknown metadata parser와 privacy defaults 구현 | REQ-SEN-006 | P1-002 | 명세 필드 fixture, malformed packet 안전 처리, body/payload 기본 미저장 |
| [ ] | P1-005 | Flow repository adapter와 ClickHouse ingestion/read query 구현 | REQ-ARC-001, REQ-PER-001 | P0-006,P1-003 | chunk insert/query, schema/version/checksum, no full materialization test |
| [ ] | P1-006 | Detector/Evidence/AnalysisContext 인터페이스 및 공통 목적지 detector 구현 | REQ-DET-001, REQ-DET-002 | P1-005 | 독립 detector test, metrics/evidence 반환, benign policy hook |
| [ ] | P1-007 | score aggregation/severity와 candidate 저장/read API 최소 경로 구현 | REQ-SCR-001, REQ-SCR-002, REQ-SCR-003, REQ-RES-001 | P1-006 | 0/39/40/59/60/79/80/100 경계, cap/감점/근거, candidate API 계약 |
| [ ] | P1-008 | 최소 합성 common-destination fixture로 offline integration 작성 | REQ-TST-001, REQ-TST-003 | P1-007 | PCAP→Flow→detector→stored candidate→API가 외부 인터넷 없이 통과 |

**Gate 1:** 작은 합성 PCAP이 streaming 수집되어 실제 계산된 후보와 근거가 API에 노출된다. 가짜 후보 반환은 금지한다.

### Phase 2 — 두 센서 분산 수집·작업 상태 수직 슬라이스

| 상태 | 작업 ID | 작업 | 요구사항 | 의존성 | 완료 조건 |
|---|---|---|---|---|---|
| [ ] | P2-001 | Go live capture backend(AF_PACKET/TPACKET_V3 우선)와 interface discovery 구현 | REQ-SEN-003, REQ-SEN-004, REQ-PER-002 | P1-002,P1-003 | 권한/interface 오류 구조화, start/stop, live/offline 계약 test |
| [ ] | P2-002 | mTLS 인증서 identity, expiry/revocation과 outbound gRPC stream 구현 | REQ-ARC-002, REQ-SEC-001, REQ-SEC-002 | P0-006 | inbound 없이 연결, invalid/revoked/expired cert 거부, SENSOR scope |
| [ ] | P2-003 | sensor registration 및 10초 heartbeat/상태/clock offset 구현 | REQ-SEN-001, REQ-SEN-002, REQ-TIM-001 | P2-002 | 등록 필드 전체, unique ID, OFFLINE/DEGRADED 포함 상태/3초 skew test |
| [ ] | P2-004 | sensor/group/tag/enable/detail API 구현 | REQ-CTL-001, REQ-API-001, REQ-API-002 | P2-003 | API 정상·오류, pagination/filter/sort, 그룹 개별 선택 test |
| [ ] | P2-005 | idempotent analysis create와 상태 머신/audit 구현 | REQ-CTL-002, REQ-CTL-003, REQ-TRG-001 | P2-004 | 조건 전체 validation, 동시 같은 key 1 job, 전이/원인/시각 test |
| [ ] | P2-006 | 센서 capture command/ACK/취소와 per-sensor progress 구현 | REQ-SEN-003, REQ-UI-003, REQ-ERR-002 | P2-005 | 두 센서 command, earliest stop reason, idempotent cancel/progress |
| [ ] | P2-007 | batch upload/ingest ledger와 packet dedup/observation 보존 구현 | REQ-SEN-007, REQ-DET-009 | P2-006,P1-005 | duplicate batch 1 commit, packet count dedup, 2 sensor observations |
| [ ] | P2-008 | memory queue/file spool/reconnect/backpressure/loss report 구현 | REQ-SEN-007, REQ-PER-002 | P2-007 | 제한/age/delete-or-stop, reconnect resend, disk warning/loss controller 보고 |
| [ ] | P2-009 | 선택적 rotating PCAP upload와 metadata 연결 구현 | REQ-PCP-001, REQ-SEN-005 | P2-006 | opt-in/off, 1GB/5분/config 및 4 rotation reason, checksum/ref test |
| [ ] | P2-010 | 부분 센서 실패와 재시작 복구 수직 통합 작성 | REQ-ERR-002, REQ-TST-006 | P2-007,P2-008 | Sensor B 중단→A 분석→PARTIALLY_COMPLETED, loss/failure 표시 |

**Gate 2:** Compose의 Sensor A/B가 ONLINE이고 한 API 작업으로 캡처→Flow upload→후보 API까지 완료하며 중복/부분 실패를 견딘다.

### Phase 3 — 완전한 탐지/재분석 수직 슬라이스

| 상태 | 작업 ID | 작업 | 요구사항 | 의존성 | 완료 조건 |
|---|---|---|---|---|---|
| [ ] | P3-001 | periodic beacon detector 구현 | REQ-DET-003 | P1-006 | mean/std/CV/autocorr/jitter/size, ±10–30%, sample boundary tests |
| [ ] | P3-002 | synchronized communication detector 구현 | REQ-DET-004 | P1-006,P2-003 | 기본 2초/config window, 반복 event, skew tests |
| [ ] | P3-003 | command/attack correlation detector 구현 | REQ-DET-005 | P1-006,P2-007 | 1–30초, baseline/PPS, target/port/protocol/size/sensor, UNKNOWN negative test |
| [ ] | P3-004 | persistence/rarity detector 구현 | REQ-DET-006 | P1-006 | 장기/저량/안정/희귀 지표 및 작은 dataset warning test |
| [ ] | P3-005 | protocol/payload similarity detector 구현 | REQ-DET-007 | P1-004,P1-006 | 모든 metadata feature와 CDN 다양성 negative test |
| [ ] | P3-006 | multi-sensor context detector 구현 | REQ-DET-008, REQ-DET-009 | P2-007,P3-002 | 명세 key, ±2초, independent pattern vs mirror duplicate test |
| [ ] | P3-007 | 전체 가중치/감점/allowlist 정책 및 suppression 통계 구현 | REQ-SCR-001, REQ-SCR-002, REQ-UI-005 | P3-001..P3-006 | 7 caps, 5 감점, 5종 allowlist/expiry, 제외 통계/설명 |
| [ ] | P3-008 | Candidate 상세 read model/차트 query/설명 가능성 구현 | REQ-RES-001, REQ-RES-002 | P3-007 | host/sensor/time/metric/confidence/FP/target/PCAP 필드 계약 test |
| [ ] | P3-009 | immutable dataset snapshot, historical analysis/reanalysis 구현 | REQ-TRG-002 | P2-005,P3-007 | 원 데이터 복제 없이 새 run/parameter snapshot, missing-retention warning |
| [ ] | P3-010 | Scenario A–G deterministic generator/oracle 구현 | REQ-TST-002 | P3-009 | 각 명세 규모/패턴 생성, 고정 seed, 기대 score/evidence/status 모두 통과 |

**Gate 3:** A/B botnet은 기대 점수, C/D 정상 traffic은 HIGH 미만, E/F/G 중복·skew·부분 실패 oracle이 모두 통과한다.

### Phase 4 — 운영 API·UI·PCAP·보안 수직 슬라이스

| 상태 | 작업 ID | 작업 | 요구사항 | 의존성 | 완료 조건 |
|---|---|---|---|---|---|
| [ ] | P4-001 | 인증과 ADMIN/ANALYST/VIEWER/SENSOR RBAC 구현 | REQ-SEC-002, REQ-API-001 | P2-002 | endpoint/resource별 allow/deny matrix test |
| [ ] | P4-002 | 로그인/작업/PCAP/allowlist/sensor/config/role/delete audit 구현 | REQ-SEC-003 | P4-001 | 8종 event와 user/time/IP/action/target/result, secret redaction test |
| [ ] | P4-003 | 분석/sensor/group/allowlist API 전체와 목록 공통 query 구현 | REQ-API-001, REQ-API-002, REQ-UI-005 | P3-009,P4-001 | 명세 endpoint 20개, 정상/오류, pagination/filter/sort, OpenAPI snapshot |
| [ ] | P4-004 | 후보별 PCAP streaming export worker 구현 | REQ-PCP-002 | P2-009,P3-008 | 7종 filter, async 상태, 대용량 bounded memory, packet 정확성 test |
| [ ] | P4-005 | secure PCAP download 구현 | REQ-PCP-003 | P4-001,P4-002,P4-004 | RBAC, signed expiry, path traversal/filename/max size/access/audit tests |
| [ ] | P4-006 | Dashboard/Sensor UI 구현 | REQ-UI-001, REQ-UI-002 | P4-003 | 명세 필드/차트 렌더, loading/empty/error/accessibility test |
| [ ] | P4-007 | 분석 생성/진행/취소 UI 구현 | REQ-UI-003 | P4-003 | live/history 전체 input, progress/count/time/sensor/error/warning/cancel |
| [ ] | P4-008 | 후보 목록/상세/PCAP UI 구현 | REQ-UI-004 | P3-008,P4-005 | list/detail 요구 필드, timeline/chart/flow/export/download test |
| [ ] | P4-009 | Allowlist UI와 재분석 flow 구현 | REQ-UI-005, REQ-TRG-002 | P4-003,P4-007 | 5종/description/expiry add/delete, suppression stats, reanalyze |
| [ ] | P4-010 | Playwright E2E 9개 흐름 작성 | REQ-TST-004 | P4-006..P4-009 | login→sensor→create→progress→list→detail→export→allowlist→reanalyze 통과 |

**Gate 4:** 인증 사용자 Web UI에서 분석 생성부터 설명 가능한 결과와 안전한 PCAP 다운로드까지 완료한다.

### Phase 5 — 보관·관측성·복구·성능·문서/릴리스

| 상태 | 작업 ID | 작업 | 요구사항 | 의존성 | 완료 조건 |
|---|---|---|---|---|---|
| [ ] | P5-001 | retention policy와 background cleanup 구현 | REQ-RET-001, REQ-RET-002 | P3-008,P4-004 | 7/30/180/365/30 defaults/config, paged delete, expired PCAP 표시/audit |
| [ ] | P5-002 | 명세 metric/log/error coverage 완성 | REQ-ERR-001, REQ-OBS-001, REQ-OBS-002 | P4-003 | 10 오류와 10 metric, 필수 JSON fields, no sensitive payload test |
| [ ] | P5-003 | 장애 복구 test suite 완성 | REQ-TST-006, REQ-PER-002 | P5-001 | Controller/Redis/Worker/network/MinIO/Postgres/batch redelivery 자동 통과 |
| [ ] | P5-004 | Compose 12단계 핵심 통합 test 완성 | REQ-TST-003 | P4-005,P5-003 | 등록→job→capture→traffic→upload→worker→candidate→API→export→download→audit |
| [ ] | P5-005 | coverage gate와 API 정상/오류 suite 완성 | REQ-TST-001, REQ-TST-007 | P5-004 | backend core≥80%, detector≥90%, sensor core≥80%, 모든 API 양경로 |
| [ ] | P5-006 | 1M benchmark generator/runner/artifact 구현 | REQ-PER-001, REQ-TST-005 | P3-010,P5-004 | `make benchmark-1m`, 1M+, 전체 pipeline, JSON/MD time/peak RSS |
| [ ] | P5-007 | Sensor 100k PPS/drop 및 Flow API latency benchmark | REQ-PER-002 | P5-006 | 기준 hardware/config 기록, drop≤1%·API≤5초 목표 결과/병목 문서 |
| [ ] | P5-008 | dependency/secret/image security scan과 CI gate 완성 | REQ-SEC-001, REQ-CI-001 | P5-005 | PR/push에서 필수 검사 전체, 저장소 secret/private key 없음 |
| [ ] | P5-009 | README·deployment/operations/security 문서 작성 | REQ-DOC-001, REQ-SCP-002 | P5-008 | README 11개, 운영 9개 항목, 방어/제외 범위, 실제 command 대조 |
| [ ] | P5-010 | Implementation Report와 최종 artifact 작성 | REQ-RPT-001, REQ-DOD-001 | P5-006..P5-009 | 11 section, 미완료 정직 보고, coverage/benchmark/final test artifacts |
| [ ] | P5-011 | 최종 검증을 처음부터 수행하고 DoD sign-off | REQ-VAL-001, REQ-DOD-001 | P5-010 | 아래 VAL-001~010 및 DoD-001~024 전부 증거와 함께 통과 |

## 3. 필수 명령 계약

| 상태 | ID | 명령 | 완료 조건 |
|---|---|---|---|
| [ ] | CMD-001 | `make setup` | pinned 의존성/로컬 개발 인증서·필요 디렉터리를 멱등 준비, secret 미커밋 |
| [ ] | CMD-002 | `make build` | Go/Python/Web 및 Docker image build 성공 |
| [ ] | CMD-003 | `make up` | Compose 전체 시작 및 health 대기 성공 |
| [ ] | CMD-004 | `make down` | Compose 리소스 정상 종료(기본 데이터 파괴 금지) |
| [ ] | CMD-005 | `make lint` | Go format/vet, Python format/lint/type, TypeScript lint 통과 |
| [ ] | CMD-006 | `make test` | 최소 unit + 핵심 Compose integration 실행·통과 |
| [ ] | CMD-007 | `make test-unit` | Go/Python/TS unit와 coverage gate 통과 |
| [ ] | CMD-008 | `make test-integration` | 외부 인터넷 없이 핵심 분산 흐름 통과 |
| [ ] | CMD-009 | `make test-e2e` | Playwright 명세 9개 흐름 통과 |
| [ ] | CMD-010 | `make generate-test-pcaps` | 고정 seed Scenario A–G 생성·검증 |
| [ ] | CMD-011 | `make benchmark-1m` | 1M+ 전체 pipeline과 JSON/MD artifact 생성 |
| [ ] | CMD-012 | `make clean` | generated/build/cache/test runtime을 안전 삭제, source/fixture 보존 |

위 12개 명령 문자열을 그대로 제공한다. CI는 `lint → unit test → integration test → build → security scan` 순서를 따른다.

## 4. 최종 검증 절차

다음은 **순서 고정**이며 실패 시 원인을 수정하고 `VAL-001`부터 다시 실행한다.

| 상태 | ID | 검증 |
|---|---|---|
| [ ] | VAL-001 | `make clean` |
| [ ] | VAL-002 | `make setup` |
| [ ] | VAL-003 | `make build` |
| [ ] | VAL-004 | `make lint` |
| [ ] | VAL-005 | `make test-unit` |
| [ ] | VAL-006 | `make test-integration` |
| [ ] | VAL-007 | `make generate-test-pcaps` |
| [ ] | VAL-008 | `make test-e2e` |
| [ ] | VAL-009 | `make benchmark-1m` |
| [ ] | VAL-010 | `docker compose up -d` 후 모든 container 정상, Sensor A/B ONLINE, 합성 C2 job COMPLETED, 후보/evidence, PCAP export, DNS/NTP < HIGH, 1M OOM 없음 확인 |

결과는 `artifacts/`에 command log/테스트/coverage/`benchmark-1m.json`/`benchmark-1m.md`로 저장한다.

## 5. Definition of Done 추적표

| 상태 | DoD ID | 완료 조건 | 선행 작업/증거 |
|---|---|---|---|
| [ ] | DOD-001 | 2개 이상 Sensor가 Controller 등록 | P2-003, VAL-010 sensor 목록 |
| [ ] | DOD-002 | Sensor별 Inbound/Outbound 설정 | P1-001,P2-003 설정/API test |
| [ ] | DOD-003 | Web UI 분석 조건 입력/시작 | P4-007, E2E |
| [ ] | DOD-004 | 시간 또는 최대 packet으로 capture 종료 | P1-002,P2-006 test |
| [ ] | DOD-005 | Flow와 선택적 PCAP 중앙 저장 | P1-005,P2-009 integration |
| [ ] | DOD-006 | 복수 sensor 동일 분석 context 통합 | P2-007,P3-006 |
| [ ] | DOD-007 | 공통 목적지 detector 동작 | P1-006 fixture |
| [ ] | DOD-008 | periodic beacon detector 동작 | P3-001 Scenario A |
| [ ] | DOD-009 | synchronized communication detector 동작 | P3-002 tests |
| [ ] | DOD-010 | command 후 attack correlation 동작 | P3-003 Scenario B |
| [ ] | DOD-011 | 후보 0–100 score와 evidence | P3-007,P3-008 |
| [ ] | DOD-012 | 결과에서 관련 host/sensor 확인 | P4-008 E2E |
| [ ] | DOD-013 | 조건별 PCAP extract/download | P4-004,P4-005 E2E |
| [ ] | DOD-014 | Allowlist score 적용 | P3-007 Scenario C/D 및 UI |
| [ ] | DOD-015 | 합성 정상 traffic이 high-risk 오탐 아님 | Scenario C/D oracle |
| [ ] | DOD-016 | 합성 botnet이 기대 score 이상 | Scenario A/B oracle |
| [ ] | DOD-017 | 1M benchmark OOM 없음 | P5-006 artifacts |
| [ ] | DOD-018 | unit/integration/E2E 모두 통과 | VAL-005/006/008 |
| [ ] | DOD-019 | 핵심 분석 coverage 기준 충족 | P5-005 coverage artifact |
| [ ] | DOD-020 | Docker Compose 전체 실행 | VAL-010 health evidence |
| [ ] | DOD-021 | 비밀번호/인증서 private key 미포함 | P5-008 secret scan |
| [ ] | DOD-022 | README/운영 문서와 구현 일치 | P5-009 command/API review |
| [ ] | DOD-023 | placeholder/mock/비활성 핵심 test 없음 | repository scan + review |
| [ ] | DOD-024 | 최종 test/benchmark 결과 `artifacts/` 저장 | P5-010 artifact manifest |

## 6. 테스트 매트릭스

| 계층 | 필수 범위 | Gate |
|---|---|---|
| Sensor unit | 방향, internal/external, flow key/timeout, filter/end condition, protocol parser, spool/dedup | core line coverage ≥80% |
| Analysis unit | dedup, beacon, sync, command/attack, 모든 detector, score/allowlist, clock correction | detector line coverage ≥90% |
| Controller unit/API | validation, state transition/idempotency, retention, export filter, 정상·오류/RBAC | backend core line coverage ≥80%, 모든 API 양경로 |
| Integration | Compose 12단계, A–G, storage/queue/gRPC, partial failure | 외부 인터넷 없이 deterministic pass |
| E2E | 명세 9개 Playwright flow | 모든 browser flow pass |
| Recovery | 7개 장애와 duplicate batch | 데이터 손실/중복/상태 오류 없이 복구 또는 명시 실패 |
| Performance | 1M pipeline, peak RSS/time; 100k PPS/drop; Flow API latency | OOM/묵시적 loss 없음; 목표 미달은 병목/결과 문서화 |
| Security | dependency/image/secret scan, cert/RBAC/input/download | high/critical 정책 기준 통과, private key 없음 |

## 7. 컴포넌트 소유권(병렬 에이전트 충돌 방지)

| 경계 | 주요 경로 | 소유 계약 |
|---|---|---|
| Sensor | `sensor/`, sensor-side `proto/` consumer | packet→Flow/protocol/PCAP/spool; 점수/사용자 API 비소유 |
| Controller | `controller/`, `proto/sensor.proto` owner | identity/job/state/RBAC/REST/gRPC gateway/audit; detector math 비소유 |
| Analysis | `analysis/` | ingestion repository, detector/evidence/scoring; UI/auth 비소유 |
| Web | `web/` | OpenAPI client/UI/E2E page model; 서버 권한 판정 비소유 |
| Test tools | `tools/`, `testdata/` | deterministic PCAP/oracle/benchmark; production code에 fake result 주입 금지 |
| Platform/docs | Compose/Make/CI/`docs/`/`artifacts/` | reproducible orchestration, command contracts, release evidence |

공유 계약(`proto`, OpenAPI, DB migration, evidence schema)은 소유자가 먼저 versioned 변경하고 소비자는 계약 테스트를 갱신한다. 서로 다른 에이전트는 같은 migration 번호나 같은 generated client를 병렬 편집하지 않는다.

## 8. 위험과 의사결정 체크포인트

- **패킷 dedup 오탐:** 완전 필드가 없으면 confidence를 기록하고 과도 제거 금지; sensor observation은 항상 보존.
- **시계 오차:** 보정으로 숨기지 않고 DEGRADED/warning/confidence까지 전파.
- **ClickHouse/PostgreSQL 정합성:** DB ledger claim→chunk insert→commit/ACK의 멱등 경계와 reconciliation job 필요.
- **PCAP 개인정보/용량:** opt-in, 짧은 retention, streaming export, RBAC/signed URL/audit 적용.
- **성능 목표:** 180초/RSS8GB/100k PPS는 기준 hardware에서 측정; 목표 미달이어도 OOM/묵시적 loss는 허용하지 않고 병목을 보고.
- **MVP 과대 범위:** Phase gate마다 수직 슬라이스를 유지하고 명세 제외 기능은 구현하지 않는다.
- **중요 결정 변경:** queue/store/protocol/capture/scoring 경계 변경은 새 ADR 승인 후 진행.
