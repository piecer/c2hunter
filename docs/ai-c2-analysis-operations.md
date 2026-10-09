# AI C2 Analysis 운영 가이드

## Milestone 1 실행

기본값은 비활성이다. FakeGateway 수직 슬라이스를 실행하려면 `.env`에 다음을 설정한다.

```bash
# AI Run API를 활성화한다.
C2HUNTER_AI_ANALYSIS_ENABLED=true
# 실제 로컬 Ollama를 사용한다. fake는 deterministic test 기본값이다.
C2HUNTER_AI_MODEL_PROVIDER=ollama
C2HUNTER_AI_MODEL_BASE_URL=http://host.docker.internal:11434
C2HUNTER_AI_MODEL_NAME=qwen3.6-agent:256k
```

AI worker profile과 전체 서비스를 시작한다.

```bash
# 기존 서비스와 분리된 AI worker를 opt-in으로 시작한다.
docker compose --env-file .env --profile ai up -d --build
```

AI worker는 `c2hunter:ai:jobs`만 소비하며 기존 `c2hunter:analysis:jobs`를 사용하지 않는다. 메시지는 Run ID만 포함한다. Worker는 DB snapshot을 읽고 terminal Run이면 그대로 ack하므로 재전달에 멱등적이다. processing list와 lease 만료 복구를 사용한다.

AI worker는 시작 시 provider의 model 목록을 조회해 readiness를 확인한다. 모델이 없거나 endpoint가 닫혀 있으면 Queue를 소비하기 전에 종료한다. OpenAI-compatible endpoint는 필요할 때 `C2HUNTER_AI_MODEL_API_KEY`를 secret manager로 주입한다.

## 장애 격리

- `C2HUNTER_AI_ANALYSIS_ENABLED=false`로 Controller의 AI Run 생성을 즉시 중지할 수 있다.
- AI worker 중지/장애는 기존 Analysis Job 상태와 Candidate를 바꾸지 않는다.
- 모델 timeout은 AI Run만 `FAILED/MODEL_TIMEOUT`으로 만든다.
- schema/evidence validator 실패는 AI Run만 `FAILED/MODEL_OUTPUT_INVALID`로 만든다.
- HTTP timeout은 설정된 횟수만 재시도한 뒤 AI Run만 `FAILED/MODEL_TIMEOUT`으로 만든다.
- 실행 중 취소는 gateway retry/repair 경계에서 repository의 최신 `CANCELLED` 상태를 확인한다.
- Queue 재전달은 terminal Run 불변성과 assessment ID upsert로 중복 결과를 만들지 않는다.

## High-Recall prefilter

- prefilter는 기존 detector score를 수정하지 않는 결정론적 보조 rank다.
- `ai-prefilter-v3` factor와 score는 AI Run candidate snapshot에만 저장한다.
- common DNS/NTP, bulk transfer, trusted peer penalty는 LLM 호출 전에 적용된다.
- payload가 없고 응답/ACK이 적은 고속 outbound SYN/FIN/RST 지배 트래픽은 공격 대상일
  가능성이 높으므로 해당 control flow만 생성 후보와 신규 결정론적 evidence에서 제외한다.
  같은 peer의 UDP, inbound, ACK 및 payload flow와 기존 저장 Candidate는 유지한다.
- 동일 5-tuple과 동일 TCP initial sequence의 outbound SYN-only 전송이 최소 4회 관측되고
  0.5~120초 간격이 고정 주기 또는 2/4/6초 같은 bounded 배수 backoff를 이루면 하나의
  logical connection attempt로 deduplicate하고 `COMMUNICATION_STATUS` 후보를 함께 만든다.
  RST는 `REFUSED_OR_RESET_OBSERVED`, SYN-ACK/ACK는 `PEER_RESPONSE_OBSERVED` 또는
  `ESTABLISHED_OBSERVED`, 완료 신호가 없으면 `NO_COMPLETION_OBSERVED`로 기록한다.
- 응답 부재만으로 host/service unavailable을 확정하지 않는다. `NO_COMPLETION_OBSERVED`는
  `no_response_is_not_host_unavailable`, `capture_loss_or_asymmetry_possible` warning과 낮은
  confidence를 포함한다. timing/sequence가 없거나 truncated된 구버전·불완전 record는
  deduplicate하지 않고 기존 C2 분석 입력으로 보존한다.
- Flow가 없으면 기존 Candidate만 사용하고, 기존 Candidate가 없어도 적합한 external peer가 있으면 AI Run을 생성할 수 있다.

## 행동 기반 탐색: 1차 shadow 운영

완료/부분 완료 C2 분석 화면에서 기본 해제된 `행동 기반 탐색 사용`을 선택하고 AI
Run을 실행한다. 기존 규칙 결과는 그대로 남으며, 행동 후보의 분석 결과와 검토
범위는 별도로 표시된다. 외부 모델은 표시된 전송 대상에 대한 동의가 필요하다.
중단하려면 다음 실행부터 선택을 해제한다. 이미 저장된 Run/피드백은 삭제하지 않는다.

1차는 장기 학습기가 아니다. 같은 작업 안의 protocol/service/packet-or-aggregate
집단에서 median/MAD를 계산한다. stream당 outbound 8개, 같은 서비스 집단 8개 peer
이상이 필요하며 반복 간격, record 평균 크기 안정성, 방향별 byte 비중 중 두 종류의
독립 근거가 상대 이상이어야 한다. 균일한 정상 heartbeat 집단, 흔한 DNS/NTP,
기존 control-flood/SYN retry 제외 조건은 보수적으로 처리한다. 소수 peer만 있는
캡처나 새로운 단독 서비스는 `INSUFFICIENT_SERVICE_COHORT`로 탐색되지 않을 수 있다.

LIVE 집계 flush 간격과 min/max 크기를 패킷 시퀀스로 해석하지 않는다. 집계 입력은
반복 간격 근거를 사용할 수 없으며, 크기/방향 등 남은 근거가 충분해야 한다.
shadow의 보조 prefilter도 `ai-prefilter-shadow-v1`로 구분하며 집계 peer의 beacon/
동시 접속 factor와 그 순위 가산점을 제외한다. 기존 legacy 모드의 prefilter는 유지한다.
`PRIMARY_STREAM_ONLY`, `CAPTURE_COMPLETENESS_UNVERIFIED`, 역사 기준선 부재를
항상 구분한다. 시계 오차/누락/짧은 관측은 악성 근거가 아니라 판단 한계다.

자원 한도는 두 단계이다. shadow Run admission은 입력 100,000 flow와 결합 전 후보
2,048개를 넘으면 거절한다. 생성 peer도 집단 점수 계산 전에 2,048개 한도를 적용한다.
행동 탐색 자체는 8,192 flow, 256 peer, SYN 관측 256개,
context collection별 128개로 제한된다. 내부 한도 초과 시 행동 순위를 일부만 만들지
않고 해당 탐색을 비우며 `*_BUDGET_EXCEEDED` 경고를 남긴다. 기존 후보 검토는 남을
수 있으므로 `COMPLETED`만 보고 행동 탐색 전체 성공으로 해석하면 안 된다. 잘못된
packet count는 1로 보정하지 않는다. packet count/byte count/duration/timestamp가
없거나 잘못되면 shadow 요청을 거절하며 관측하지 않은 값을 0으로 만들지 않는다.
기록된 센서 clock offset은 행동 후보의 관측 신뢰도 감점에 전달한다.

`evaluate_shadow_job`은 운영과 같은 1–5개 선택 예산을 사용하고 선택 전 recall,
선택 후 recall, 추가 양성/오탐 및 판단 유보를 분리한다. synthetic/FakeGateway 결과는
계약 검증일 뿐 정확도 개선 증거가 아니다. 실제 라벨 검증과 false-positive 검토 전에는
자동 차단, 자동 룰 배포, 온라인 자기학습을 활성화하지 않는다.

## Splunk/MISP 초안

- 완료된 assessment마다 `SPLUNK_HUNT`, `SPLUNK_DETECTION`, `MISP_DRAFT` 3개를 생성한다.
- SPL은 read-only profile validator, MISP는 unpublished/IOC/internal-IP validator를 통과한 경우만 저장한다.
- 승인과 거절은 조사 workflow 상태이며 외부 시스템 전송을 의미하지 않는다.
- regenerate는 새 PENDING artifact ID를 만들고 이전 review 이력을 덮어쓰지 않는다.

## 확인

```bash
# Compose 구성이 유효한지 확인한다.
docker compose --env-file .env --profile ai config --quiet

# worker 상태를 확인한다.
docker compose --env-file .env --profile ai ps ai-worker

# AI 전용 테스트를 실행한다.
.venv/bin/pytest -q controller/tests/test_ai_analysis.py controller/tests/test_ai_analysis_api.py controller/tests/test_ai_worker.py
```

## DB migration/rollback

Controller 시작 시 additive `CREATE TABLE IF NOT EXISTS`로 다음 객체를 만든다.

- `ai_analysis_runs`
- `ai_candidate_assessments`
- Job/Run 및 Run/assessment 조회 index

rollback은 먼저 `C2HUNTER_AI_ANALYSIS_ENABLED=false`로 신규 요청을 중지하고 AI worker를 내린 뒤, 보존 정책에 따라 백업 후 다음 순서로 수행한다.

```sql
-- AI 전용 데이터만 제거한다. 기존 Analysis Job/Candidate 테이블은 건드리지 않는다.
DROP TABLE IF EXISTS ai_candidate_assessments;
DROP TABLE IF EXISTS ai_analysis_runs;
```

SQLite도 같은 이름의 두 테이블과 index를 제거한다. 감사 이벤트는 보존 의무 때문에 rollback 시 자동 삭제하지 않는다.

## 현재 제한

Ollama structured grammar는 backend/model 조합에 따라 복잡한 schema와 큰 output budget을 동시에 거부할 수 있다. 현재 Ollama adapter는 normalized schema를 마지막 trusted instruction으로 전달하고 JSON mode 출력에 동일한 strict validator를 적용한다. OpenAI-compatible adapter는 native `json_schema`를 사용한다. SPL/MISP draft는 후속 Phase에서 추가한다.
