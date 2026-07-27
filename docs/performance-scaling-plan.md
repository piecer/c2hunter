# C2Hunter 성능·확장성 개선 계획

## 목표

실제 운영 입력에서 처리량, 지연, 메모리, 데이터 손실을 함께 측정하고 병목을 단계적으로 제거한다. 합성 패킷 생성 속도만 빠른 상태를 성능 완료로 간주하지 않는다.

## 2026-07-27 기준선과 확인된 병목

### 기존 100만 패킷 벤치마크

| 항목 | 결과 |
|---|---:|
| 합성 패킷 | 1,000,000 |
| 생성 Flow | 704,992 |
| detector 입력 Flow | 12,706 |
| 전체 시간 | 3.18초 |
| 최대 RSS | 33.4MiB |
| 손실 | 0 |

기존 `tools/benchmark/benchmark.py`는 모든 패킷을 chunk 처리하지만 detector에는 최대 20,000개의 대표 Flow만 전달한다. 따라서 ingestion 구현의 제한 메모리는 확인하지만 실제 worker가 대형 job의 전체 Flow를 객체화하고 분석하는 비용은 측정하지 않는다.

### 실제 detector 입력 확장 프로파일

1,000개 외부 후보, 후보당 100개, 총 100,000 Flow를 `run_detectors`에 직접 전달했다.

| 항목 | 개선 전 | 1차 개선 후 |
|---|---:|---:|
| detector 전체 시간 | 266.8초 | 2.91초 |
| `PersistenceRarityDetector` | 260.8초 | 선형 경로로 변경 |
| Python 호출 수 | 3.05억 | 대규모 중첩 재순회 제거 |

원인은 `PersistenceRarityDetector`가 후보마다 전체 Flow grouping을 다시 수행한 O(후보 수 × Flow 수) 구현이었다. grouping 결과와 후보 수를 한 번 계산해 O(Flow 수 + 후보 수)로 변경했다.

최신 `master` 통합 후 동일한 100,000 Flow 규모를 다시 측정한 결과 detector 실행은 0.812초, 프로세스 최대 RSS는 약 75MiB였다. 입력 생성과 interpreter 시작을 포함한 wall time은 1.12초였으며 성능 목표를 계속 만족한다.

## 우선순위

### P0 — 확정된 비선형 detector 제거

상태: 1차 완료

- `PersistenceRarityDetector`의 후보별 전체 재-grouping 제거
- 후보 수와 무관하게 grouping 호출이 한 번인지 회귀 테스트로 보장
- 10만 Flow 프로파일을 같은 입력으로 전후 비교

완료 조건:

- 회귀 테스트 통과
- 10만 Flow detector 실행 10초 이내
- 기존 detector 결과와 점수 의미가 동일

### P0 — Sensor 패킷 hot path의 전체 Flow 스캔 제거

상태: 1차 완료

`Aggregator.AddWithMetadata`가 패킷마다 모든 활성 Flow의 idle timeout을 검사해 O(패킷 수 × 활성 Flow 수)로 동작했다. runtime에는 이미 idle timeout 절반 주기의 명시적 `Expire` ticker가 있으므로 다음과 같이 역할을 분리했다.

- 패킷 hot path는 현재 5-tuple key만 O(1)로 확인
- 같은 key가 idle timeout 뒤 재등장하면 기존 Record를 종료하고 새 Record 생성
- 다른 key의 idle Record는 runtime ticker의 명시적 sweep에서 정리
- 활성 Flow 10,000개 benchmark를 회귀 측정 도구로 추가

| 활성 Flow 10,000개에서 Add | 개선 전 | 개선 후 |
|---|---:|---:|
| 시간/op | 133.8~139.6µs | 61.4~65.5ns |
| 할당/op | 0 | 0 |

동일 기준 호스트에서 약 2,100배 단축됐다.

완료 조건:

- 같은 key의 idle 경계 분리 테스트 통과
- 다른 key는 패킷 hot path가 아닌 명시적 sweep에서 만료됨을 테스트
- Go race test와 전체 sensor test 통과

### P1 — 정직한 기준선과 관측성

상태: 다음 작업

- 전체 worker 경로를 `DB load → JSON decode → Flow 객체화 → detector → scoring → result JSON → DB/Redis publish` 단계로 분리 측정
- 대표 window 벤치마크와 전체 분석 벤치마크를 분리하고 결과 schema에 측정 범위를 명시
- 입력 크기를 10만, 50만, 100만 Flow로 늘려 시간과 peak RSS 기울기 기록
- detector별 duration, 입력 Flow 수, 후보 수, evidence 수를 metrics에 노출
- queue depth/oldest age, worker job duration, job payload bytes, result bytes, PostgreSQL query duration을 수집

완료 조건:

- CI용 소형 성능 회귀 테스트와 수동 대형 benchmark 명령 존재
- 동일 seed 결과가 JSON artifact로 남음
- 100만 Flow worker peak RSS와 각 단계 시간이 보고됨

### P1 — 분석 공통 인덱스 재사용

상태: 계획

현재 여러 detector가 `scoped_flows()`와 candidate grouping을 각각 다시 계산한다. job당 한 번 다음 read-only 인덱스를 만들고 detector들이 공유하도록 변경한다.

- scoped Flow sequence
- candidate → `(internal_host, Flow)` rows
- internal host → Flow rows
- direction/time 기반 command-attack 조회 인덱스
- candidate traffic profile

주의사항:

- 인덱스 자체가 Flow를 복제하지 않고 기존 객체 참조만 보유해야 한다.
- `CommandAttackDetector`의 후보별 전체 Flow 스캔을 host/time 조회로 교체한다.
- signature matching은 protocol/direction/service-port로 먼저 bucket한 뒤 내용 특징을 비교한다.

완료 조건:

- detector 결과 동등성 테스트 통과
- 100만 Flow에서 detector 단계 60초 이내
- 공통 인덱스 포함 worker peak RSS 2GiB 이내를 1차 목표로 설정

### P0 — 제어 API pagination을 저장소까지 전달

상태: 계획

현재 API의 page/page_size는 저장소에서 전체 행/JSONB를 읽은 뒤 Python에서 자른다. 특히 전역 후보 API는 모든 job과 모든 candidate set을 역직렬화한다.

개선 범위:

- `list_jobs`, `list_candidates`, `list_flow_labels`, `list_payload_signatures`에 filter/sort/limit/offset 또는 cursor 계약 추가
- candidate를 job별 JSONB 배열 하나가 아닌 조회 가능한 행 구조로 정규화
- candidate ID를 전역 조회·수정·삭제할 수 있는 인덱스 추가
- job status/source/created_at, flow label job_id/created_at에 실제 컬럼 또는 expression index 추가
- 목록 응답과 count 쿼리를 분리하고 필요한 필드만 projection

완료 조건:

- page size 50 요청에서 DB가 최대 50개 item만 반환
- 100만 candidate 보유 시 목록 p95 500ms 이내
- candidate 단건 조회/수정/삭제가 전체 job scan 없이 수행

### P0 — PostgreSQL 연결 모델 개선

상태: 계획

Controller가 하나의 공유 psycopg connection과 전역 lock을 사용하므로 동시 API 요청이 직렬화된다. read 경로 일부는 lock 없이 같은 connection을 공유한다.

- psycopg connection pool 도입
- 요청/트랜잭션 단위 connection 사용
- `_audit`을 호출자 transaction과 같은 cursor/transaction에서 처리해 중첩 commit 제거
- read-only 요청의 불필요한 commit 제거
- pool 대기 시간, active/idle connection, transaction duration 계측

완료 조건:

- 동시 50 요청 부하에서 connection 사용 오류와 직렬화 병목 없음
- API p95/p99와 pool wait가 기준 이내
- 감사 이벤트와 상태 변경의 원자성 유지

### P0 — 대형 Flow 저장·로딩을 chunk/columnar 경로로 전환

상태: ClickHouse query spike 완화 완료, end-to-end streaming 계획

현재 job별 전체 Flow를 하나의 PostgreSQL JSONB 값으로 저장하고 worker가 한 번에 list와 `Flow` 객체로 만든다. 이는 문서의 ClickHouse chunk query 설계와 다르며 단일 job 크기가 커질수록 DB row rewrite, JSON decode, Python heap이 함께 증가한다.

최신 `master`에서는 ClickHouse snapshot의 `FINAL`과 global sort를 제거하고 `PREWHERE`, `max_threads`, `max_memory_usage`를 적용했다. 월 단위 partition과 TTL migration도 추가되어 ClickHouse query/merge spike는 완화됐다. 다만 HTTP response 전체 decode→tuple과 PostgreSQL job snapshot→worker list materialization은 그대로이므로 이 항목 전체가 완료된 것은 아니다.

- PostgreSQL은 compact job metadata와 immutable snapshot 참조만 유지
- Flow는 ClickHouse 파티션 또는 chunk row로 저장
- worker 입력을 candidate/time partition 단위 iterator로 제공
- detector 계약을 전체 `Sequence[Flow]` 의존에서 bounded partition/aggregate 의존으로 단계적 전환
- 결과 evidence도 크기 상한과 상세 object 참조를 분리

완료 조건:

- 100만 Flow job에서 단일 JSONB materialization 없음
- worker 메모리가 입력 Flow 수에 비례해 무제한 증가하지 않음
- 재시도 시 동일 dataset snapshot을 읽고 결과가 결정적

### P1 — PCAP parsing과 upload/export 메모리 상한

상태: 계획

현재 upload는 요청 전체를 `bytearray`에 받은 뒤 `bytes`로 복사하고, parser가 모든 packet record를 다시 보유한다. 기본 500MiB/200만 packet 허용치에서 동시 요청은 Controller OOM으로 이어질 수 있다. 또한 payload SimHash가 작은 PCAP parsing CPU의 약 90%를 차지했고 payload SHA-256이 두 번 계산된다.

- upload를 임시 object/file로 streaming하고 parser 입력도 seekable stream으로 전환
- packet record를 chunk 단위 Flow aggregation으로 넘겨 전체 packet list 제거
- payload feature 결과의 SHA-256을 재사용해 중복 hash 제거
- SimHash shingle list materialization을 iterator/rolling window로 변경
- export도 전체 원본·필터 결과·출력 bytearray 동시 보유를 피하고 multipart stream으로 전환

완료 조건:

- 500MiB upload 한 건의 Controller 추가 RSS가 256MiB 이하
- 동시 4건에서 OOM 없이 backpressure 또는 명시적 429/503 반환
- 동일 PCAP의 Flow/evidence 결과 동등성 유지
- parser benchmark에 bytes, packets, duration, peak RSS, payload-feature 비중 기록

### P1 — Worker 수평 확장과 queue 효율

상태: 계획

- worker concurrency를 설정 가능하게 하고 job ID 단위 lease/멱등 완료를 검증
- `recover_expired`를 매 receive마다 전체 만료 집합 조회하지 않고 제한 batch/주기 실행
- 긴 job의 visibility lease 갱신 추가
- result payload가 커지면 Redis list에 전체 결과를 싣지 않고 DB/object reference만 publish
- 부하 테스트에서 queue depth, oldest age, retry, duplicate completion을 검증

완료 조건:

- worker 수 증가에 따라 독립 job 처리량이 선형에 가깝게 증가
- 장시간 job이 실행 중 중복 전달되지 않음
- worker 강제 종료 후 유실 없이 재처리

### P0 — Sensor capture와 spool/upload I/O 분리

상태: 다음 작업

- capture loop가 현재 batch JSON 생성, spool 쓰기, pending 전체 scan, HTTP upload와 ACK 삭제를 동기적으로 기다린다. bounded producer/consumer queue와 별도 uploader goroutine으로 분리한다.
- spool `Pending()` 전체 디렉터리 scan을 매 persist/drain/metric refresh마다 반복하지 않도록 in-memory index 또는 page iterator를 둔다.
- uploader concurrency와 inflight bytes를 제한하고 첫 실패가 capture를 막지 않도록 retry scheduler를 분리한다.
- shutdown 시 capture → aggregate → spool의 durable 경계까지만 보장하고 HTTP drain은 제한 시간 안에서 수행한다.
- Go benchmark와 pprof로 packet decode, flow key, payload feature, batch encode allocation을 측정
- 100k PPS에서 CPU, allocation/op, lock wait, packet drop을 기록
- queue/spool 상한과 축소 정책을 부하 테스트
- HTTP batch 압축과 payload 크기별 처리량 비교
- 디스크 가득 참, controller 지연, 네트워크 단절에서 bounded memory와 명시적 loss telemetry 검증

완료 조건:

- 기준 호스트 100k PPS에서 drop ≤1%
- 장시간 controller 중단에도 메모리 상한 유지
- spool 복구 후 중복은 멱등 처리되고 손실량은 보고됨

### P3 — Web 대량 목록

상태: 계획

- 모든 목록 filter/sort/page를 서버에 전달
- Dashboard는 전체 job 목록 대신 aggregate endpoint 사용
- 200개 이상 행은 pagination 또는 virtualized table 적용
- 상세 evidence/traffic bucket은 필요할 때만 fetch

완료 조건:

- 10만 job/candidate 환경에서도 브라우저가 전체 목록 JSON을 다운로드하지 않음
- 주요 화면 LCP 2.5초 이내, interaction block 200ms 이하

## 실행 순서

1. 완료: detector와 Sensor Add hot path의 비선형 경로 제거
2. Sensor capture loop에서 spool/upload I/O 분리 및 장애 주입 부하 테스트
3. PostgreSQL connection pool과 transaction/audit 경계 개선
4. repository pagination과 candidate 정규화
5. 전체 worker benchmark/metrics와 공통 분석 인덱스 추가
6. `CommandAttackDetector` 비선형 경로와 payload signature 비교 인덱스 개선
7. Flow 저장소 chunk/ClickHouse 전환
8. PCAP upload/parser/export streaming 전환
9. worker 수평 확장, Redis lease recovery, web aggregate API 순으로 진행

각 단계는 기능 회귀 테스트를 먼저 추가하고, 동일 데이터셋의 전후 benchmark를 함께 남긴다. 한 번에 여러 계층을 바꾸지 않는다.
