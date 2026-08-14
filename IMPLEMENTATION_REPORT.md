# Implementation Report

기준일: 2026-08-14

이 문서는 `SPEC.md` §32 형식을 따르며, 완료되지 않은 항목을 완료로 표시하지 않는다.

## 구현 완료 기능

- Go Sensor의 capture, flow/protocol metadata, spool/retry, Controller HTTPS API 전송
- Sensor enrollment, agent token, heartbeat/configuration, rotate/revoke
- 분석 작업, 결정론적 detector/scoring, candidate/evidence, allowlist, PCAP export
- Web 기반 sensor/job/candidate/AI/TI/MISP analyst workflow
- bounded Evidence 기반 AI assessment, feedback, 안전한 SPL/MISP draft
- VirusTotal/AbuseIPDB enrichment와 single-flight/pacing/shutdown 경계
- PostgreSQL/ClickHouse/Redis/MinIO adapter 및 Compose 개발 배포

세부 요구 상태는 `TASKS.md`의 행별 상태를 권위로 사용한다.

## 전체 아키텍처

Sensor는 Controller에 outbound HTTPS 요청을 보내며 enrollment 후 agent token을 `X-Sensor-Token` header로 사용한다. Controller API가 권위 상태와 RBAC를 담당하고 Redis queue를 통해 Analysis/AI Worker에 작업을 전달한다. PostgreSQL은 트랜잭션 상태, ClickHouse는 Flow, MinIO는 PCAP/artifact, Redis는 전달·cache 경계다. 현재 전송 계약은 `docs/adr/0003-sensor-https-token-transport.md`에 기록했다. `proto/sensor.proto`의 gRPC service는 구현된 gateway가 아닌 향후 설계 초안이다.

Controller의 `create_app()`은 여전히 큰 composition root지만 Payload Signature, Detector Weight Preset, Sensor Group, Allowlist, Operations API를 repository/service-injected `APIRouter` 5개로 분리했다. `app.py`는 4,142줄에서 3,966줄로 줄었고, lifecycle 결합 domain은 동일한 vertical-slice 패턴으로 후속 분리한다.

## 사용 기술과 선택 이유

- Go: Linux Sensor의 bounded capture/runtime
- Python 3.12, FastAPI, Pydantic: API·계약 검증·분석 생태계
- React/TypeScript/Vite: analyst UI와 browser E2E
- PostgreSQL/ClickHouse/MinIO/Redis: OLTP, time-series Flow, binary artifact, queue/cache 책임 분리
- Docker Compose/Make: 단일 host 개발·검증 재현

버전은 lockfile과 manifest에 고정한다. Compose의 제3자 runtime image는 읽을 수 있는 tag와 immutable digest를 함께 사용한다.

## C2 탐지 로직

독립 detector가 versioned Evidence를 만들고 scoring 모듈이 contribution/adjustment를 0–100으로 정규화한다. 동일 양방향 TCP 5-tuple은 configurable idle timeout(기본 60초)으로 재사용 연결을 분리하며, session별 byte/packet threshold를 넘으면 proxy/relay 오탐 억제를 위해 기본 score cap 20을 적용한다. analyst exact payload signature는 cap 예외다.

`make backtest-high-volume`은 8개 curated labeled case 중 정책 영향 대상 4개(`high_volume && !analyst_exact_match`)에서 현행 cap 20, strong-evidence cap 40, 고정 -25를 같은 triage threshold 40으로 비교한다. cap 20은 C2 recall 0.00/FPR 0.00/queue 0, strong-evidence cap 40은 0.50/0.00/1, 고정 -25는 1.00/1.00/4다. artifact는 `artifacts/high-volume-policy-backtest.{json,md}`다. production historical label은 저장소에 없으므로 작은 fixture 결과만으로 default cap은 변경하지 않았다.

## 테스트 결과

2026-08-14 실제 실행 결과:

- `make lint`: Ruff/format/mypy, Go vet, ESLint, tracked ELF, Ruff S 전 규칙, gosec 전 규칙 통과
- `make test`: Go package tests 통과; Controller+Analysis 488 passed/1 storage integration skipped; AI Worker 12 passed; tool tests 3 passed; Web 77 passed
- `make test-coverage`: Controller 80.17%, Analysis 86.55%, detector 92.65%, Sensor aggregate 69.4%, Sensor core 80.7%로 모든 gate 통과
- `make build`: Python compile, Go/Web/sensor tarball, Controller/Worker/Web Docker image build 통과
- `make test-e2e`: Playwright 9 passed
- `docker compose --env-file .env config --quiet`, `git diff --check`: 통과

## Coverage 결과

CI에 다음 차단 gate를 추가했다.

- Controller package gate: 80% 이상(실측 80.17%)
- Analysis package baseline: 86% 이상(실측 86.55%)
- `c2hunter_analysis.detectors`: 90% 이상(실측 92.65%)
- Sensor aggregate baseline: 69% 이상(실측 69.4%)
- Sensor core: TASKS 필수 8 package aggregate 80% 이상(실측 80.7%)

`production.py` 등 adapter별 저커버리지는 총합 수치로 가려질 수 있다. 핵심 coverage 기준 `DOD-019`는 완료했지만 모든 API의 정상/오류 양경로는 아직 완료되지 않아 `P5-005`는 PARTIAL이다.

## 100만 패킷 Benchmark 결과

기존 2026-08-02 artifact 기준 packet loss 0, OOM 없음, 316,166.12 packets/s, peak RSS 33.25 MiB가 기록돼 있다. 이번 변경에서 benchmark를 새로 실행하기 전에는 이 값을 신규 결과로 주장하지 않는다.

## 알려진 제한사항

- Controller `app.py`의 나머지 domain router 분리가 미완료다.
- Sensor mTLS gRPC gateway는 구현되지 않았고 HTTPS/`X-Sensor-Token`이 현재 계약이다. 원격 `http://` Controller URL은 기본 거부하며 로컬 개발은 명시적 `C2HUNTER_ALLOW_INSECURE_CONTROLLER=true`가 필요하다.
- enrollment claim token은 URL path에 포함되지만 Uvicorn access log filter와 metrics path normalization에서 마스킹한다. 외부 reverse proxy에도 동일한 redaction 정책이 필요하다.
- in-memory session/rate limiter는 multi-process/HA 권위 저장소가 아니다.
- `HIGH_VOLUME_TCP_SESSION`은 idle timeout sessionization을 사용하지만 SYN/FIN/RST 경계를 완전히 복원하지 못한다. curated labeled backtest는 추가됐으나 historical production label은 없다.
- Ruff S/gosec blanket exclusion은 제거됐고 active finding은 각각 0이다. 동적 SQL, deterministic RNG, local admin path와 bounded packet conversion의 오탐은 source rationale가 있는 line-specific suppression으로 제한한다.
- Sensor 100k PPS/drop과 전체 Compose 12단계 live sign-off가 미완료다.
- 프로젝트 권리자 선택에 따라 canonical Apache License 2.0 본문을 `LICENSE`에 추가하고 README에 명시했다.

## 운영 시 주의사항

- production에서 dev-login을 활성화하면 설정 검증 단계에서 기동을 거부한다.
- Sensor와 사용자 API는 HTTPS로 보호하고 agent/static token을 secret manager로 주입한다.
- `C2HUNTER_TRUSTED_PROXY_CIDRS`에는 직접 연결되는 reverse proxy만 넣는다. 넓은 사설망 CIDR은 X-Forwarded-For 위조 경계를 넓힌다.
- public Ollama/OpenAI-compatible endpoint를 사용하면 Evidence metadata가 조직 경계를 벗어나며 Controller와 AI Worker에서 startup warning이 발생한다. 조직 데이터 반출 정책 승인이 필요하다.
- digest 갱신은 tag별 multi-architecture manifest를 확인하고 scan/test 후 수행한다.

## 향후 개선 항목

1. sensors/jobs/candidates/pcap/auth/admin/ai/integrations 중 lifecycle 결합 domain을 작은 APIRouter slice로 계속 추출한다.
2. HIGH_VOLUME 정책 후보를 production historical label로 재실행하고 strong-evidence cap 40 채택 여부를 결정한다.
3. line-specific SAST suppressions를 safe query/path/conversion abstraction으로 계속 축소한다.
4. Sensor 100k PPS benchmark gate를 추가한다.
5. Redis-backed session/rate limiter 도입을 multi-instance 배포 선행 조건으로 둔다.
6. Sensor HTTPS override와 enrollment path redaction을 reverse proxy 운영 설정까지 검증한다.
7. Docker/Compose digest 갱신을 architecture별 자동화하고 정기 rebuild 정책을 추가한다.

## Definition of Done 검증표

`TASKS.md` DOD-001~024를 권위 표로 사용한다. 현재 명시적으로 미완료/부분 완료인 핵심 항목은 다음과 같다.

| DoD | 상태 | 원인 | 현재 동작 범위 | 재현/후속 작업 |
|---|---|---|---|---|
| DOD-001 | PARTIAL | Compose Sensor A/B live sign-off 없음 | Sensor 등록 API/agent 구현 | Compose 12단계 실행 |
| DOD-019 | DONE | 핵심 component coverage gate 충족 | Controller 80/Analysis 86/detector 90/Sensor core 80 및 aggregate 69 ratchet | `make test-coverage` |
| DOD-020 | PARTIAL | 전체 서비스 live 검증 결과 미갱신 | `docker compose config` 검증 | `make up` 후 health/flow 확인 |
| DOD-021 | PARTIAL | full dependency/secret live sign-off 필요 | Ruff S/gosec 전 규칙 active finding 0, digest pin 및 기존 security scan | final security artifact 재생성 |
| DOD-022 | PARTIAL | legacy mTLS/certificate 문구와 운영 절차 전체 재감사 필요 | ADR-0003과 핵심 deployment 문서는 현재 계약 반영 | README/docs 전체 consistency audit |
| DOD-023 | PARTIAL | repository 전체 placeholder 재감사 필요 | 핵심 테스트 활성 | 독립 audit 수행 |
| DOD-024 | PARTIAL | 이번 최종 artifact manifest 미작성 | 기존 benchmark artifact 존재 | 최종 명령 로그 저장 |

P5-010은 이 보고서 구조를 갖췄지만 선행 P5-008/P5-009와 최종 artifact가 미완료이므로 DONE으로 올리지 않는다. P5-011 최종 sign-off도 완료로 주장하지 않는다.
