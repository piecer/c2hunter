# C2Hunter 외부 AI 제어 절차

## 문서 선택과 버전

- 일반 기능: 저장소의 `docs/external-api-reference.md`.
- AI Run: `docs/ai-c2-analysis-api.md`.
- 배포 서버의 `/docs`, `/openapi.json`: 실제 배포 버전의 경로와 요청 스키마 확인. UI 프록시가 이 경로를 전달하지 않으면 운영자가 지정한 Controller 주소로 확인한다. 포트를 추측하거나 외부에 서비스를 노출하지 않는다.
- 이 번들의 `operations.json`은 허용된 24개 작업과 권한을, `openapi.json`은 소스에서 생성한 전체 스키마를 담는다. 기준 커밋은 operations.json의 source_commit이다. 새 소스가 운영에 배포됐다는 뜻은 아니다.
- 기존 REST 문서의 센서 분석 예시는 일부 필수 필드를 생략한다. 현재 AnalysisJobCreate에는 name, idempotency_key, sensor_ids, mode, start_time, end_time, capture, analysis, internal_networks가 필요하다. duration/packet 제한은 analysis가 아니라 capture 객체에 있다. 최신 스키마를 우선한다.
- 인증은 미들웨어에도 구현되어 있다. OpenAPI에 security 항목이 없더라도 익명 접근 가능으로 해석하지 않는다. 수동 파싱되는 historical-baseline 요청/페이지 항목은 OpenAPI만으로 완전하게 설명되지 않는다.

## 인증과 실행 환경

운영자가 비밀 관리 도구로 C2HUNTER_API_TOKEN을 프로세스 환경에 주입한다. 명령행 인수·채팅·저장 파일·디버그 로그에 토큰을 쓰지 않는다. C2HUNTER_BASE_URL에는 승인된 origin만 넣는다. 예: 로컬 호스트에서는 http://127.0.0.1:9001, 원격에서는 운영자의 HTTPS 주소. 실제 주소는 운영자가 결정한다.

VIEWER는 일반 조회, ANALYST는 분석/AI 실행·취소와 evidence 조회 권한이다. 저장된 baseline-comparisons/baseline-sources도 ANALYST가 필요하다. scope 변경·정상 이력 승인·외부 내보내기·데이터 삭제 등 관리 작업은 이 클라이언트에 없다. 센서 내부 X-Sensor-Token 인증과 사람/외부 AI의 Bearer 인증을 혼용하지 않는다.

이 도구는 static token만 사용한다. 개발 로그인·토큰 발급·자동 갱신·로그아웃·전역 설정 변경을 수행하지 않는다. 최소 권한의 전용 토큰을 운영자가 발급하고 필요 시 운영자 측에서 폐기한다. 인증 거절 시 다른 계정이나 개발 로그인으로 우회하지 않는다.

## 1. 읽기 전용 사전 확인

    python scripts/client.py describe
    python scripts/client.py request openapi-get
    python scripts/client.py request health
    python scripts/client.py request ready
    python scripts/client.py request capabilities
    python scripts/client.py request sensors-list
    python scripts/client.py request jobs-list --query page=1 --query page_size=20

OpenAPI 조회도 인증이 켜진 서버에서는 Bearer 토큰이 필요하다. ready 성공과 AI 모델 가용성은 별개다. capabilities.remote는 서버가 모델로 보내는 전송 대상이다. 클라이언트가 원격에서 접속한다는 의미가 아니다. 모델 정보·후보 데이터도 외부 AI에 전달될 수 있으므로 조사 데이터 반출 정책을 먼저 확인한다.

## 2. PCAP 분석

예제 파일의 이름·파일명·내부망·맥락·멱등 키를 실제 승인 범위에 맞게 수정한다. 제공된 10.0.0.0/8은 샘플일 뿐이다. 동일한 예제 키를 여러 조사에 재사용하지 않는다.

    python scripts/client.py request pcap-initiate --json examples/pcap-initiate.json --allow-write

응답의 job ID를 기록한 뒤 같은 ID에 원본 PCAP/PCAPNG 바이트를 보낸다. multipart가 아니라 raw binary다.

    python scripts/client.py request pcap-upload --param job_id=JOB_ID --binary capture.pcap --allow-write
    python scripts/client.py watch job-get --param job_id=JOB_ID --max-polls 20 --interval 3
    python scripts/client.py request job-candidates --param job_id=JOB_ID --query page=1 --query page_size=20

서버의 기본 업로드 제한과 이 도구의 제한은 다를 수 있다. 도구는 최대64MiB, JSON 입력1MiB, 응답2MiB로 제한한다. 서버 설정이 더 작으면 서버 제한을 따른다. 큰 파일을 임의 분할하거나 잘라 원본 근거를 바꾸지 않는다. 201/202는 작업 접수이지 분석 완료가 아니다. PARTIALLY_COMPLETED 결과에서는 누락·경고를 유지한다.

## 3. 센서 기반 LIVE/HISTORICAL 작업

`describe job-create`의 정확한 생성 스키마를 따른다. 실제 센서 ID와 내부망, timezone이 있는 시작/종료 시간, 분석 종류를 지정한다. 이 클라이언트는 서버보다 엄격하게 capture.duration_seconds, max_packets, max_bytes 세 값을 모두 양수 정수로 요구하며 duration_seconds는 최대86400이다. 없는 필드로 capture를 대신하거나 기본값을 무제한 캡처 권한으로 해석하지 않는다.

    python scripts/client.py request job-create --json approved-job.json --allow-write

이 스킬 작성/설치는 실제 캡처 권한이 아니다. 특정 패킷 수·포트·BPF·초당 전송률이 승인됐다면 그대로 유지한다. readiness가 실제 캡처 리더 획득을 증명하기 전에는 검증용 트래픽을 보내지 않는다. 이 API 클라이언트 자체는 센서 데이터 경로가 정상임을 입증하지 않는다.

## 4. AI 분석 요청과 결과 조회

원본 job이 COMPLETED/PARTIALLY_COMPLETED인지 확인하고 원본 모듈에 맞는 analysis_kind를 사용한다: c2→C2, network_anomaly→NETWORK_ANOMALY, ddos_attack→DDOS_ATTACK. 예제는 C2 전용 shadow이며 다른 종류에는 discovery_mode=legacy가 필요하다.

    python scripts/client.py request ai-create --param job_id=JOB_ID --json examples/ai-create.json --allow-write
    python scripts/client.py watch ai-get --param run_id=RUN_ID --max-polls 20 --interval 3
    python scripts/client.py request ai-selection --param run_id=RUN_ID --query offset=0 --query limit=20
    python scripts/client.py request ai-assessments --param run_id=RUN_ID
    python scripts/client.py request assessment-get --param assessment_id=ASSESSMENT_ID
    python scripts/client.py request assessment-evidence --param assessment_id=ASSESSMENT_ID

job ID, run ID, assessment ID는 서로 다르다. 후보가 없거나 모델이 실패했다고 원본 분석을 자동 재시작하지 않는다. allow_remote=true는 별도의 명시적 반출 동의와 --allow-remote-model이 필요하다. 클라이언트 후보 기본값은1, 서버 기본값은5이며 서버 상한은5다. 후보 수가 모델 호출 수와 같지는 않다. 출력 보정과 서버의 transport retry 설정도 모델 예산에 영향을 준다. 클라이언트에는 mutation retry가 없다.

기준선 이력 기능은 기본 off다. historical 요청은 승인된 scope/generation과 유효한 비교 참조가 필요하다. 이 스킬은 baseline_reference를 추측해 만들거나 정상 이력을 자동 승인하지 않는다. 기존 승인 참조와 정확한 요청 계약이 없으면 중단하고 운영자에게 요청한다. 읽기 작업은 제공한다:

    python scripts/client.py request baseline-scopes --query offset=0 --query limit=20
    python scripts/client.py request baseline-scope --param scope_id=SCOPE_UUID
    python scripts/client.py request baseline-comparisons --param run_id=RUN_ID --query offset=0 --query limit=20
    python scripts/client.py request baseline-sources --param run_id=RUN_ID --query offset=0 --query limit=20

## 페이지네이션과 상태

- jobs/AI run 목록: page/page_size, page는1부터, page_size 최대200. 반환된 total과 page_size에 맞게 다음 페이지를 요청한다. 첫 페이지만 보고 전부라고 보고하지 않는다.
- 선택 목록: offset 0..2048, limit 1..50, 서버 next_offset을 따른다.
- 저장된 기준선 비교: offset 0..128, limit 1..50. 저장된 기준선 source: offset 0..16, limit 1..50. 둘 다 next_offset을 따른다.
- scope 목록은 별도 수동 파서다: offset 0..16, limit 1..20, 중복·앞자리0·공백·비ASCII 숫자를 허용하지 않는다.
- AI: QUEUED/PREPARING/ANALYZING/VALIDATING → COMPLETED/FAILED/CANCELLED.
- job: 생성/대기/캡처/업로드/수집/분석을 거쳐 COMPLETED/PARTIALLY_COMPLETED/FAILED/CANCELLED.
- watch의 유한 관측 예산 소진은 INCOMPLETE다. 실패/취소/부분 완료를 완전 성공으로 바꾸지 않는다. 더 긴 관측은 별도 승인된 읽기로 수행한다. timeout은 자동 취소를 뜻하지 않는다.
- 각 요청의 소켓 대기와 읽기 크기는 제한되지만 플랫폼의 DNS 해석은 엄밀한 전체 wall-clock 상한을 보장하지 못할 수 있다.

## CLI 출력과 종료 코드

- request 성공: stdout의 JSON `{status, data}`, 종료0. 분석 완료 여부는 data.status를 별도로 확인한다.
- 일반 오류: stderr의 고정 JSON `{error, http_status, write_outcome_unknown}`, 종료2. 원본 오류 body·URL·예외 문자열은 출력하지 않는다.
- watch 완료: stdout의 성공 JSON에 state=COMPLETED와 polls가 추가되며 종료0.
- watch 부분 완료/실패/취소/관측 미완료: stderr의 오류 JSON, 각각 종료3/4/5/6. 알려진 상태와 관측 횟수를 유지하며 알 수 없는 서버 상태 문자열은 진단에 복사하지 않는다.
- watch의 max-polls는1..100(기본20), interval은1..3600초(기본3), 요청 timeout은1..60초(기본10)다. 전체 운용 시간을 무제한으로 늘리지 말고 승인된 관측 예산 안에서 선택한다.
- 경로 ID에는 영문·숫자·밑줄·하이픈·점을 허용하며 길이는1..200이다. `.`/`..` 단독, slash, percent 등은 거절한다. 서버보다 보수적인 클라이언트 제한이며 ID를 잘라내거나 고쳐 보내지 않는다.

## 실패와 취소

401은 자격 증명 확인,403은 권한 부족이다. 409는 상태·모듈·멱등 키·원격 동의 등의 충돌일 수 있다. 422는 요청 형식을 수정해야 한다. 429/503에 자동 재시도하지 않는다.

네트워크 실패,5xx,리다이렉트,잘못된/과대 응답을 쓰기 후 받으면 접수 여부가 불확실할 수 있다. 과거에는 durable admission 뒤 오류 응답이 발생한 사례도 있다. 기록한 ID가 있으면 GET으로 확인하고, 없으면 jobs-list/ai-list를 빠짐없이 조회해 노출되는 식별 정보와 비교한다. 이 도구에는 임의의 by-idempotency-key URL이 없다. 식별을 확정할 수 없으면 불확실 상태를 보고하고 운영자가 조정하도록 한다. 새 키로 맹목 재제출하지 않는다.

취소는 해당 작업에 대해 별도로 승인된 경우만 수행한다:

    python scripts/client.py request ai-cancel --param run_id=RUN_ID --json examples/cancel.json --allow-write
    python scripts/client.py request job-cancel --param job_id=JOB_ID --json examples/cancel.json --allow-write

실패한 기존 요청을 성공으로 덮어쓰거나 원래 데이터를 삭제하지 않는다. 보고에는 사실, AI 해석, coverage/uncertainty, 실제 실행 상태를 구분한다.

## 검증 종류

- client unittest: 자체 가짜 loopback HTTP 서버와 합성 토큰으로 transport/권한 플래그/제한/실패 처리를 검증한다.
- producer contract test: C2HUNTER_SOURCE_ROOT를 로컬 저장소 경로로 설정하고 프로젝트의 설치된 Python으로 `python -m unittest discover -s tests -p test_producer_contract.py -v`를 실행한다. 모델·DB는 in-memory/FakeGateway이며 실제 서비스에 접속하지 않는다.
- exporter --check: 같은 소스의 OpenAPI/선택 operation snapshot과 정확한 바이트 일치 확인.
- 위 검증은 외부 AI 제품에 도구 등록, 운영 서버 인증, 실제 모델 성공, 실제 LIVE 수집 또는 운영 배포를 검증했다는 뜻이 아니다.
