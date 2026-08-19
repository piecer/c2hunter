# Candidate 대량 선별 및 MISP 자동화 기능 명세

상태: 검토 요청(Draft)

이 문서는 Candidate가 대량 발생하는 환경에서 목록 중심으로 선별·처리하고, 외부 TI 판정과
MISP Event 등록을 자동화하기 위한 요구사항과 구현 경계를 정의한다. 문서 검토와 승인 전에는
구현을 시작하지 않는다.

## 1. 배경과 목표

현재 C2Hunter는 Candidate 목록에서 필터·정렬과 External TI 요약을 제공하지만, 판정·후속 조치·
MISP 전송은 Candidate 상세 화면에서 개별 수행한다. Candidate가 많으면 화면 전환과 반복 입력이
분석가의 병목이 된다. 또한 MISP 전송 대상은 하나의 기본 Event로만 취급되어 “관리를 위한 등록”과
“즉시 차단이 필요한 지표 전달”을 분리할 수 없다.

이번 기능의 목표는 다음과 같다.

1. Candidate 목록에서 여러 항목을 선별하고 상세 화면 진입 없이 일괄 처리한다.
2. Candidate 생성 시 관리용 MISP Event에 자동 등록할 수 있다.
3. 외부 TI 공급자 중 2개 이상이 명확한 양성일 때 즉시조치용 MISP Event에 자동 등록할 수 있다.
4. 관리용 Event와 즉시조치용 Event를 서로 다른 Event ID로 운영한다.
5. 외부 TI/MISP 연동과 자동화 정책을 `.env`가 아니라 WebUI에서 관리한다.
6. 자동화 결과를 재시도 가능하고 감사 가능한 별도 resource로 보존한다.

## 2. 용어

- 관리 Event: 새 Candidate를 조사·추적하기 위해 등록하는 MISP Event.
- 즉시조치 Event: 방화벽·SOAR 등 후속 시스템이 차단 대상으로 소비하는 MISP Event.
- 두 Event는 C2Hunter가 새로 생성하는 Event가 아니라 ADMIN이 지정한 기존 MISP Event다. 초기
  범위는 Event 존재·쓰기 권한을 연결 시험에서 검증하고 그 Event에 attribute를 추가하는 데 한정한다.
- 양성 공급자: 구성된 판정 규칙에 따라 악성 신호를 반환한 외부 TI 공급자. 한 공급자의 여러
  지표는 공급자 1개로만 계산한다.
- 일괄 처리: 현재 페이지 선택 또는 필터에 명시적으로 선택된 Candidate 집합에 같은 명령을 적용하는
  작업. 서버가 보이지 않는 전체 검색 결과를 암묵적으로 처리하지 않는다.
- 자동화 실행: Candidate와 정책 버전을 입력으로 생성되는 관리 등록 또는 즉시조치 등록 작업.

## 3. 범위

### 포함

- Candidate 목록의 체크박스 선택, 현재 페이지 전체 선택, 선택 상태 요약, 일괄 처리 도구 모음
- 목록에서 판정 저장, 후속 조치 상태 변경, 외부 TI 재조회, 관리 Event 등록, 즉시조치 Event 등록
- Candidate 생성 후 관리 Event 자동 등록
- 외부 TI 2개 이상 양성 시 즉시조치 Event 자동 등록
- WebUI 기반 외부 TI/MISP 설정, 연결 시험, 비밀 값 교체와 자동화 활성화
- 설정·정책·자동화 실행 이력과 실패 사유 감사
- 중복 등록 방지, 제한된 병렬 처리, 재시도
- Controller 프로세스 안의 외부 TI/MISP HTTP 요청을 직렬화하고, 각 요청 완료 후 다음 요청 시작 전
  `threat_intel_request_delay_seconds`(기본 1초, 0~60초)를 적용한다. 한 Candidate의
  VirusTotal/AbuseIPDB 조회를 포함해 다른 Candidate 조회나 MISP 조회·등록도 동시에 실행하지 않는다.
- Controller shutdown은 요청 간 delay 대기를 즉시 중단하고 아직 시작하지 않은 enrichment 작업을
  취소한다. 이미 시작한 HTTP 요청만 설정된 request timeout 범위에서 종료를 기다린다.

### 제외

- C2Hunter가 방화벽 또는 EDR에 직접 차단 명령 전송
- MISP Event 자체의 생성·게시·삭제·권한 관리
- 기존 detector 점수 변경 또는 외부 TI를 detector score에 합산
- 외부 TI의 `NO_SIGNAL`을 안전 판정으로 취급
- 모든 운영·인증·DB 연결 설정을 WebUI로 이전

즉시조치 Event 등록은 차단 시스템이 소비할 지표를 MISP에 전달하는 단계다. 실제 차단 성공 여부는
외부 시스템의 피드백 연동 전까지 C2Hunter의 `action_status=COMPLETED`로 자동 간주하지 않는다.

## 4. 사용자 경험

### 4.1 Candidate 목록 중심 선별

Candidate 목록의 각 행과 헤더에 선택 체크박스를 제공한다. 필터나 페이지가 바뀌면 기존 선택은
초기화하고 사용자에게 초기화 사실을 알린다. 기본 page size는 기존 50개를 유지하고 API의 최대
200개 경계를 넘지 않는다.

목록 상단의 일괄 처리 도구 모음은 선택 개수와 다음 명령을 제공한다.

- 검토 시작: `UNDER_REVIEW` 판정과 공통 메모 저장
- 확정 C2: `CONFIRMED_C2` 판정, confidence, 공통 메모 저장
- 오탐: `FALSE_POSITIVE` 판정과 공통 메모 저장
- 조치 시작 / 조치 완료: 기존 판정·상태 전이 규칙을 그대로 적용
- 외부 TI 다시 조회
- 관리 Event에 등록
- 즉시조치 Event에 등록

파괴적이거나 외부 시스템에 쓰는 명령은 실행 전에 대상 수, Event 이름/ID, 예상 제외 수를 확인하는
확인 대화상자를 표시한다. 전체 성공으로 뭉뚱그리지 않고 Candidate별 `SUCCEEDED`, `SKIPPED`,
`FAILED` 결과와 오류 코드를 보여준다. 실패한 항목만 다시 실행할 수 있어야 한다.

목록에는 다음 자동화 상태를 compact badge로 추가한다.

- 관리 등록: 대기 / 등록됨 / 실패 / 비활성
- 즉시조치: 기준 미충족 / 대기 / 등록됨 / 실패 / 수동 등록
- 외부 TI: 기존 `ti_assessment`의 상태, 양성 공급자 수, 공급자 coverage

### 4.2 WebUI 설정

ADMIN 전용 `Settings > Threat intelligence & MISP` 화면을 추가한다.

연동 설정:

- VirusTotal 활성화. API key는 기존 배포 환경에서만 주입
- AbuseIPDB 활성화, 조회 기간, 양성 confidence threshold. API key는 기존 배포 환경에서만 주입
- MISP 활성화, URL, TLS 검증. API key는 기존 배포 환경에서만 주입
- 공급자 timeout
- 연결 시험: 저장 전 입력값 시험과 저장된 설정 시험을 구분

자동 조회 설정:

- Candidate 자동 조회 활성화
- Job당 최대 Candidate 수
- worker 수와 queue capacity

즉시조치 자동화를 활성화하면 그 정책의 severity/score 필터를 통과한 모든 Candidate가 자동 TI 조회
대상이어야 한다. 기존처럼 Job당 상위 N개만 조회하는 제한 때문에 대상이 누락되는 설정은 저장을
거부하거나, 제한을 만족하는 별도 즉시조치 조회 queue를 사용한다. 조회되지 않은 Candidate는 기준
미충족이 아니라 `NOT_EVALUATED`로 표시한다.

MISP 자동화 설정:

- 관리 Event ID
- Candidate 생성 시 관리 Event 자동 등록 활성화
- 즉시조치 Event ID
- 즉시조치 자동 등록 활성화
- 즉시조치 최소 양성 공급자 수. ADMIN이 2 이상 범위에서 설정
- 자동화 대상 최소 detector severity 또는 score. 기본값은 제한 없음
- attribute type. 현재 Candidate 계약에 맞춰 초기 버전은 `ip-src`로 고정
- MISP comment template의 제한된 변수: Candidate ID, Job ID, detector severity, 양성 공급자 수

화면은 Event ID 두 값이 동일하면 저장을 거부한다. 즉시조치 자동화를 켤 때는 최소 2개의 TI 공급자가
활성화되어 있어야 하며, 연결 시험에 성공하지 않은 MISP 설정은 자동화를 활성화할 수 없다.

API key는 WebUI/API/DB로 이전하지 않고 기존 `.env` 또는 배포 secret manager에서만 읽는다. 설정 API는
비밀 값과 그 유무도 반환하지 않으며 UI에 입력·교체·삭제 메뉴를 제공하지 않는다.

## 5. 양성 공급자 판정

초기 버전은 다음의 설명 가능한 규칙을 사용한다.

| 공급자 | 양성 조건 | 공급자 가중치 |
|---|---|---|
| VirusTotal | `malicious > 0` 또는 `suspicious > 0` | 1 |
| AbuseIPDB | `abuse_confidence_score >= ADMIN 설정 threshold` | 1 |
| MISP | 검색 결과의 유효한 외부 Event가 1개 이상 | 1 |

`COMPLETED` 또는 성공 결과가 보존된 `PARTIAL` 조회의 성공 공급자만 양성 개수에 포함한다.
`PENDING`, `FAILED`, 인증 오류, rate limit, timeout은 음성이 아니라 미확정이다. 공급자 2개 이상이
양성이어도 최소 2개 공급자의 조회가 성공했다는 coverage 조건을 함께 만족해야 한다.

초기 구현은 기존 `ti_assessment.positive_providers` 계산을 단일 판정 함수로 추출해 목록 projection과
자동화가 같은 규칙을 사용하게 한다. 향후 provider별 threshold를 설정으로 노출하기 전까지 별도 규칙을
두지 않는다.

## 6. 자동화 순서와 안전 경계

### 6.1 Candidate 생성 처리 순서

1. detector Candidate 원본을 저장한다.
2. 설정된 범위 안에서 외부 TI 조회 작업을 생성한다.
3. 관리 Event 자동 등록 작업을 생성한다.
4. TI 조회가 종료되면 저장된 조회 snapshot으로 즉시조치 자격을 평가한다.
5. 자격을 충족하면 즉시조치 Event 자동 등록 작업을 생성한다.

관리 Event 등록 성공을 기다리느라 분석 Job의 `COMPLETED` 전이를 막지 않는다. 자동화 작업은 bounded
executor/queue에서 수행하며, queue overflow와 종료 중 거부도 실패 resource로 저장한다.

### 6.2 자기증폭 방지

Candidate를 관리 Event에 먼저 등록하면 이후 MISP 검색에서 자기 자신이 양성으로 집계될 수 있다.
이 결과가 “외부 TI 2개 이상 양성”을 인위적으로 충족하면 즉시조치 오탐이 발생한다. 이를 막기 위해
다음을 모두 적용한다.

1. 즉시조치 판정은 관리 등록 작업보다 먼저 시작된 TI lookup snapshot만 사용한다.
2. MISP 양성 판정에서 현재 설정의 관리 Event ID와 즉시조치 Event ID를 제외한다.
3. lookup record에 평가에 사용한 `settings_version`, 제외 Event ID, 공급자별 양성 판정 근거를 저장한다.
4. 설정 변경 후 과거 lookup을 새 정책으로 자동 재평가하지 않는다. 관리자가 명시적으로 재조회하거나
   재평가해야 한다.

### 6.3 자동 판정과 조치 상태

ADMIN이 설정한 최소 개수 이상의 외부 TI가 양성이면 시스템 actor가 먼저 즉시조치 Event 등록 성공을
확인한 뒤 `CONFIRMED_C2` verdict와 후속 `PENDING` action을 기록한다. MISP 등록에 실패하면 자동 판정은
생성하지 않고 실패 이력만 남긴다. 자동 판정에는 `origin=AUTOMATION`, 사용한 lookup ID, settings
version, 양성 공급자와 threshold를 남겨 분석가 판정과 구분한다. MISP 등록 성공은
확인하지만 실제 차단 성공 callback은 이번 범위에 포함하지 않으므로 `action_status`는 자동으로
`COMPLETED` 처리하지 않는다.

목록과 이력에서는 “자동 확정 C2”와 “분석가 확정 C2”를 origin badge로 구분한다. 두 판정은 같은 immutable
verdict resource 계약을 사용하되 actor, trigger, 정책 근거를 반드시 제공한다.

## 7. 설정 저장과 비밀 값 보호

WebUI 설정은 Controller의 런타임 `Settings` 객체나 `.env`를 수정하지 않는다. 별도 전역 integration
settings resource로 Repository에 영속화한다.

권장 저장 모델:

- `integration_settings`: 공개 설정, 활성화 상태, 단조 증가 version, 수정자, 수정 시각
- `integration_test_result`: provider, settings version, 성공 여부, 안전한 오류 코드, 시험 시각

VirusTotal, AbuseIPDB, MISP API key는 이번 범위에서 기존 `.env`/secret manager 주입을 유지한다. Event
ID, provider 활성화, timeout, 조회 기간, 자동 조회와 자동화 기준 같은 비밀이 아닌 운영 정책만
Repository에 저장한다. WebUI에서 provider를 활성화했지만 해당 API key가 배포 설정에 없으면 연결 시험과
실행은 안전한 `CREDENTIAL_NOT_CONFIGURED` 상태로 실패한다.

현재 `create_app()`에서 `.env` 기반으로 한 번 생성하는 `ThreatIntelService`와 `MispClient`는 동적 설정을
반영할 수 없다. 구현 시 settings version별 immutable client snapshot/factory로 교체한다. 실행 중 설정이
바뀌어도 이미 시작된 lookup/export는 시작 당시 version과 client snapshot을 끝까지 사용한다.
worker 수와 queue capacity도 현재 시작 시 생성되는 `ThreadPoolExecutor`와 `BoundedSemaphore`에 묶여
있으므로, 새 설정 version용 scheduler를 원자적으로 교체하고 이전 scheduler는 진행 중 작업이 끝난 뒤
종료한다. 단순히 `Settings` 필드만 갱신해서 적용된 것처럼 표시하면 안 된다.

최초 실행 시 API key를 제외한 기존 `.env` 운영 값을 version 1 WebUI 설정으로 한 번 가져온다. 이후에는
DB/WebUI 설정이 비밀이 아닌 운영 정책의 유일한 기준이며 `.env` 변경을 다시 반영하지 않는다. API key는
계속 매 실행 시 배포 환경에서만 읽는다. 가져오기 완료 여부를 저장해 재시작·다중 인스턴스에서도 중복
가져오기를 막는다.

## 8. 데이터 모델

### 8.1 Integration settings

필수 필드:

- `id`: 전역 고정 ID
- `version`: optimistic concurrency용 정수
- `providers`: provider별 enabled 및 공개 설정. API key 제외
- `candidate_auto_enrichment`: enabled, limit, workers, queue capacity
- `misp_automation`: management event, immediate-action event, 최소 양성 공급자 수(2 이상),
  AbuseIPDB 양성 threshold(0~100), 필터, template
- `updated_by`, `updated_at`

수정은 `expected_version`을 요구하고 충돌 시 409를 반환한다. 매 수정 전후 값은 비밀을 제외해 감사한다.

### 8.2 Candidate automation action

기존 MISP export 이력과 호환되는 별도 action resource에 다음을 저장한다.

- `id`, `candidate_id`, `job_id`, `candidate_ip`
- `kind`: `MANAGEMENT_REGISTRATION` 또는 `IMMEDIATE_ACTION_REGISTRATION`
- `origin`: `AUTO` 또는 `MANUAL` 또는 `BULK_MANUAL`
- `event_id`, `attribute_type`, `comment`
- `status`: `PENDING`, `EXPORTED`, `ALREADY_EXPORTED`, `SKIPPED`, `FAILED`
- `eligibility`: 양성 공급자 수, 공급자 목록, lookup ID
- `settings_version`
- `attempt_count`, `error_code`, `error_message`
- `created_by`, `created_at`, `completed_at`

중복 방지 키는 `(candidate_id, kind, event_id, attribute_type, value)`다. Event가 변경되면 새 Event로의
등록은 별도 작업으로 허용한다. 프로세스 내 lock만 사용하지 말고 Repository 수준 unique constraint나
원자적 create-if-absent로 여러 Controller 인스턴스에서도 중복을 막는다.

### 8.3 Bulk operation

일괄 처리는 요청 수명 안에서 수십 개의 외부 호출을 동기 실행하지 않는다. `candidate_bulk_operation`
resource를 생성하고 bounded worker가 항목별 작업을 수행한다.

- 최대 Candidate ID 200개
- 요청 idempotency key 필수
- 명령, 공통 입력, 요청자, 생성 시각
- 전체/대기/성공/건너뜀/실패 개수
- Candidate별 결과와 오류 코드
- 상태: `PENDING`, `RUNNING`, `PARTIAL`, `COMPLETED`, `FAILED`

## 9. API 계약 초안

> **구현 상태**: 본 섹션은 Draft 상태의 API 계약 초안이다. 현재 구현된 endpoint는 `POST /api/v1/candidate-bulk-operations`과 `GET/PUT /api/v1/integration-settings`뿐이다.
> 미구현 endpoint는 아래 표의 "미구현" 열을 참조한다.

ADMIN 전용 설정 API:

| endpoint | 상태 |
|---|---|
| `GET /api/v1/integration-settings` | 구현됨 |
| `PUT /api/v1/integration-settings` | 구현됨 |
| `POST /api/v1/integration-settings/test` | **미구현** |
| `POST /api/v1/integration-settings/import-environment` | **미구현** |

목록 중심 처리 API:

| endpoint | 상태 |
|---|---|
| `POST /api/v1/candidate-bulk-operations` | 구현됨 |
| `GET /api/v1/candidate-bulk-operations/{operation_id}` | **미구현** |
| `POST /api/v1/candidate-bulk-operations/{operation_id}/retry-failures` | **미구현** |

자동화 관찰·수동 실행 API:

| endpoint | 상태 |
|---|---|
| `GET /api/v1/candidates/{candidate_id}/automation-actions` | **미구현** |
| `POST /api/v1/candidates/{candidate_id}/automation-actions` | **미구현** |
| `POST /api/v1/candidates/{candidate_id}/immediate-action/re-evaluate` | **미구현** |

권한:

- 목록 조회와 자동화 상태 조회: VIEWER
- 일괄 판정·TI 재조회·조치 상태 기록: ANALYST
- 설정 조회: 민감 값이 제거된 응답에 한해 ADMIN
- 설정 수정·환경 가져오기·MISP 수동/일괄 등록: ADMIN
- 자동 실행의 actor: `SYSTEM`, trigger와 settings version을 별도 기록

기존 `POST /api/v1/candidates/{id}/misp-exports`는 호환성을 위해 유지하되 내부적으로
`MANAGEMENT_REGISTRATION` 수동 action을 생성하도록 전환한다. 명시적 Event ID를 전달한 기존 요청의
동작과 중복 방지 응답은 유지한다.

## 10. 실패 처리와 운영 정책

- 외부 TI/MISP 장애가 Candidate 저장과 분석 완료를 롤백하지 않는다.
- 인증 오류와 잘못된 Event ID는 자동 재시도하지 않고 설정 오류로 집계한다.
- timeout, rate limit, 일시적 5xx만 bounded exponential backoff로 재시도한다.
- 자동 재시도 횟수와 마지막 오류는 action resource에 기록한다.
- API key, Authorization header, MISP 전체 오류 body는 로그·응답·감사 데이터에 저장하지 않는다.
- 설정을 비활성화하면 신규 작업 생성을 중단하되 진행 중 snapshot은 완료시킨다.
- Event ID를 변경해도 과거 이력은 수정하지 않는다.
- 대량 backlog, 실패율, queue capacity 초과, provider latency를 metrics와 Dashboard attention에 노출한다.

## 11. 기존 코드와의 변경 지점

- `controller/src/c2hunter_controller/config.py`
  - 배포 bootstrap 설정과 WebUI 관리 integration 설정의 경계 분리
- `controller/src/c2hunter_controller/repositories.py`
  - versioned settings, encrypted secret metadata, bulk operation, automation action 저장 계약
  - 다중 인스턴스 중복 방지 원자 연산
- `controller/src/c2hunter_controller/production.py`
  - PostgreSQL 저장 계약과 unique constraint/트랜잭션 구현
- `controller/src/c2hunter_controller/integrations.py`
  - settings version별 client factory와 MISP 제외 Event 검색 지원
- `controller/src/c2hunter_controller/app.py`
  - 기존 Candidate enrichment 이후 eligibility 평가
  - 관리/즉시조치 자동화 scheduler와 bulk API
  - 기존 MISP export endpoint 호환 adapter
- `controller/src/c2hunter_controller/schemas.py`
  - 설정·연결 시험·bulk operation·automation action request/response
- `controller/src/c2hunter_controller/security.py`
  - 새 설정 및 MISP write endpoint의 ADMIN 권한
- `web/src/App.tsx`
  - Candidate 선택·bulk toolbar·항목별 결과
  - Settings 화면과 두 MISP Event 정책
- `web/src/styles.css`
  - 선택 상태, sticky bulk toolbar, automation badge, 반응형 설정 화면

`app.py`와 `App.tsx`가 이미 큰 파일이므로 구현 시 integration settings와 Candidate bulk UI를 별도 모듈로
추출하되, 이번 기능과 무관한 전면 리팩터링은 하지 않는다.

현재 글로벌 Candidate 목록은 `list_candidate_sets()`로 Job별 Candidate JSON 전체를 메모리에 읽어
필터·정렬하고, Candidate 갱신도 Job 배열 재저장 경로를 사용한다. 이 방식은 과다 발생 상황의 핵심
요구와 충돌한다. 구현 시 목록 projection, workflow/TI/automation 상태와 bulk 대상 조회를 후보 단위로
검색할 수 있는 정규화된 저장 구조 또는 동등한 서버 측 인덱스를 추가한다. API pagination 이후에만
Candidate 상세 JSON을 합성하고, bulk operation은 200개 ID를 한 번에 원자 갱신하지 말고 항목별
트랜잭션과 결과를 기록한다. Memory/SQLite/PostgreSQL adapter는 같은 contract를 제공해야 한다.

## 12. 수용 기준

- `CTM-001`: Candidate 목록에서 1~200개를 선택하고 상세 화면 없이 지원 명령을 실행할 수 있다.
- `CTM-002`: 필터/페이지 변경 시 숨은 선택이 남지 않고 사용자에게 초기화가 안내된다.
- `CTM-003`: 일괄 결과는 Candidate별 성공·건너뜀·실패를 표시하고 실패만 재시도할 수 있다.
- `CTM-004`: 관리 자동 등록이 켜진 상태에서 새 Candidate마다 관리 Event 등록 action이 정확히 한 번 생성된다.
- `CTM-005`: 성공 공급자 중 서로 다른 2개 이상이 양성일 때만 즉시조치 action이 생성된다.
- `CTM-006`: 실패·미조회 공급자를 음성으로 계산하지 않으며 coverage 부족 시 자동 등록하지 않는다.
- `CTM-007`: 관리/즉시조치 Event에서 발견된 MISP match는 즉시조치 양성 개수에서 제외된다.
- `CTM-008`: 관리 Event 등록 때문에 즉시조치 기준이 자기충족되지 않는다.
- `CTM-009`: 동일 Candidate·종류·Event·값은 동시 요청과 재시작 후에도 중복 등록되지 않는다.
- `CTM-010`: 관리 Event와 즉시조치 Event가 같으면 설정 저장이 거부된다.
- `CTM-011`: WebUI에서 설정 변경 후 Controller 재시작 없이 신규 작업에 새 version이 적용된다.
- `CTM-012`: 실행 중 작업은 시작 당시 settings version을 사용한다.
- `CTM-013`: API key는 API 응답, 로그, 감사 이력, 오류 메시지에 노출되지 않는다.
- `CTM-014`: MISP 또는 TI 장애가 Candidate 저장과 분석 완료를 막지 않는다.
- `CTM-015`: 자동 즉시조치 자격 충족 시 근거가 있는 `CONFIRMED_C2` verdict와 `PENDING` action을
  정확히 한 번 기록하며 실제 조치 완료 상태는 위조하지 않는다.
- `CTM-016`: VIEWER/ANALYST는 설정 수정과 MISP write를 수행할 수 없다.
- `CTM-017`: 기존 단일 Candidate TI 조회와 MISP export API 계약이 유지된다.
- `CTM-018`: 모바일 폭에서 bulk toolbar와 설정 폼을 키보드와 스크린리더로 사용할 수 있다.
- `CTM-019`: 즉시조치 정책 대상이 자동 조회 상위 N개 제한 때문에 누락되지 않으며, 미조회 대상은
  `NOT_EVALUATED`로 구분된다.
- `CTM-020`: 글로벌 Candidate 목록은 전체 Job Candidate JSON을 애플리케이션 메모리에서 전량
  스캔하지 않고 서버 측 필터·정렬·pagination을 수행한다.

구현 상태 메모:

- score, severity, suppressed 여부와 일반 정렬을 사용하는 기본 Candidates 큐는 정규화 테이블에서
  `COUNT`, `ORDER BY`, `LIMIT`, `OFFSET`을 수행한다.
- verdict, workflow, TI 파생 필터와 `ti_priority` 정렬은 정확한 결과를 유지하기 위해 현재 이력
  projection을 애플리케이션에서 결합한다. `CTM-020`을 완전히 종료하려면 decision/action/TI 최신 상태를
  후보 검색 projection에 트랜잭션으로 동기화하고 세 adapter의 page query에 같은 필터를 추가해야 한다.

## 13. 테스트 계획

### Controller

- 양성 공급자 판정의 provider별 경계와 PARTIAL/FAILED/PENDING 처리
- 관리 Event 및 즉시조치 Event 제외에 따른 MISP count 회귀
- Candidate 저장 → TI lookup → eligibility → 두 Event action 순서
- queue overflow, shutdown, timeout, rate limit, 인증 실패
- idempotency와 다중 worker 동시성
- settings optimistic concurrency, 동적 적용, 실행 중 snapshot 불변성
- scheduler 교체 중 신규/진행 작업의 settings version 일관성과 graceful drain
- 비밀 값 암호화 round-trip과 모든 공개 contract의 redaction
- RBAC 및 감사 event
- Memory, SQLite, PostgreSQL repository contract 동등성
- Candidate 대량 데이터에서 서버 측 filter/sort/pagination과 query count/메모리 경계

### Web

- 행 선택, 현재 페이지 선택, 필터/페이지 변경 시 초기화
- bulk 명령 확인, 진행률, partial failure, 실패 재시도
- 자동화 badge와 empty/loading/error 상태
- 설정 유효성, Event ID 충돌, 비밀 값 유지/교체/삭제
- 권한 없는 사용자에게 설정·MISP write 동작 미노출

### E2E

- 다수 Candidate를 필터링하고 일부를 확정·관리 등록
- TI 2개 양성 Candidate만 즉시조치 Event로 자동 등록
- 관리 Event의 self-match가 즉시조치를 유발하지 않음
- WebUI 설정 변경 후 새 Candidate에 새 Event가 적용됨
- 중복 클릭·새로고침·worker 재시작에도 MISP attribute가 중복되지 않음

완료 gate는 `make lint`, `make test`, `make build`, Playwright E2E, `git diff --check`다.

## 14. 구현 단계

1. 양성 판정 함수를 단일화하고 self-match 제외 회귀 테스트를 먼저 추가한다.
2. Candidate 목록 projection과 bulk 대상 조회를 서버 측에서 처리할 저장/index 경계를 구현한다.
3. versioned integration settings와 비밀 값 저장 계약을 Memory/SQLite/PostgreSQL에 구현한다.
4. 동적 integration client factory와 설정/연결 시험 API를 구현한다.
5. automation action의 원자적 idempotency와 version별 bounded scheduler를 구현한다.
6. Candidate 생성·TI 완료 경로에 관리/즉시조치 자동화를 연결한다.
7. bulk operation API와 worker를 구현한다.
8. WebUI Settings와 Candidate bulk toolbar를 구현한다.
9. 운영/API/데이터 모델 문서를 갱신하고 전체 gate를 실행한다.

각 단계는 테스트를 먼저 추가하는 RED-GREEN-REFACTOR 방식으로 진행한다. 설정 저장과 자동화 action이
안정화되기 전에는 WebUI만 먼저 연결하지 않는다.

## 15. 승인된 구현 결정

1. 즉시조치 최소 양성 공급자 수는 ADMIN WebUI에서 2 이상으로 설정한다.
2. AbuseIPDB 양성 confidence threshold는 ADMIN WebUI에서 설정한다.
3. Candidate 생성 시 관리 Event 자동 등록은 기본 OFF이며 ADMIN이 활성화한다.
4. 즉시조치 Event 자동 등록은 기본 OFF이며 ADMIN이 활성화한다.
5. 즉시조치 기준 충족 시 시스템이 근거가 있는 `CONFIRMED_C2` 판정과 `PENDING` action을 자동 생성한다.
6. 이번 범위의 완료 경계는 MISP attribute 등록 성공 확인까지이며 실제 차단 callback은 후속 범위다.
7. API key는 WebUI로 이전하지 않고 기존 `.env` 또는 배포 secret manager 주입을 유지한다.
8. API key 외 운영 설정은 최초 실행 시 한 번 가져온 뒤 Repository/WebUI 값만 사용한다.
9. Job별 Candidate JSON은 후보 단위 정규화 테이블로 이관하며 최초 실행 시 기존 데이터를 변환한다.
