# 분석가 주도 C2 탐지 개발 계획

기준 명세는 `docs/human-guided-detection.md`다. 구현 중 판단이 달라지면 코드보다 명세와
수용 기준을 먼저 갱신한다.

## Phase 1. 공통 Payload 특징 계약

### 변경

- `analysis/src/c2hunter_analysis/payload_features.py`
  - SHA-256, prefix SHA-256, Shannon entropy, printable ratio, FNV-1a 기반 SimHash
  - Hamming distance와 structural 비교 함수
- `analysis/.../domain.py`, `controller/.../schemas.py`
  - Flow에 비가역 특징 필드 추가
- `analysis/.../pcap.py`
  - PCAP 정규화 시 특징 계산
  - 명시적 preview 요청에만 bounded `payload_sample_hex` 생성
- `sensor/internal/payloadfeature/`, `sensor/internal/flow/`, `sensor/internal/flowbatch/`
  - Python과 같은 알고리즘으로 첫 Payload 특징 생성·전송

### 검증

- Python/Go가 동일 test vector에 같은 hash, prefix hash, entropy, printable ratio,
  SimHash를 생성
- 빈 Payload, 1~2 bytes, binary, text, 최대 sample 경계
- 기본 Flow/감사/Job에 raw Payload 미포함

## Phase 2. 탐지 엔진 개선

### 변경

- `AnalystPayloadSignatureDetector`
  - active signature snapshot을 읽어 EXACT/STRUCTURAL Evidence 생성
  - protocol/direction/service-port guard 적용
  - signature provenance와 비교 metrics 제공
- `SingleHostCompositeBeaconDetector`
  - 주기성, Payload/size 안정성, 저용량을 동시에 만족할 때만 Evidence 생성
- scoring
  - `ANALYST_PAYLOAD_SIGNATURE` cap 80
  - `SINGLE_HOST_BEACON` cap 35
  - EXACT analyst signature에 한해 single-host 감점 면제

### 검증

- exact, one-byte mutation structural, 다른 port/protocol, 비활성 profile
- 불규칙/대용량/불안정 Payload single-host benign counterexamples
- allowlist와 DNS/NTP/CDN 감점 회귀

## Phase 3. 라벨·Signature 저장 및 API

### 변경

- Repository contract와 Memory/SQLite/PostgreSQL adapter
  - flow label append
  - payload signature 생성/조회/버전 수정/비활성화
  - label/signature는 `controller_objects`, job별 immutable snapshot은
    `job_payload_signatures`에 compact Job metadata와 분리해 영속화
- Flow review helper
  - deterministic `flow_id`
  - bounded snapshot과 필터
  - 외부 service port 계산
- API
  - Flow 목록/preview
  - C2/BENIGN 라벨 생성
  - C2 라벨에서 signature 생성
  - signature 목록/수정/활성화
- 분석 enqueue
  - 활성 signature를 Job별 별도 immutable snapshot
  - Controller inline 경로와 Worker 경로가 같은 snapshot 사용

### 검증

- label provenance, latest verdict, signature conflict
- 잘못된 job/flow/signature와 threshold 입력 오류
- preview max 256 bytes, source PCAP 부재, raw Payload 비영속
- reanalysis는 최신 signature snapshot, 기존 완료 Job은 불변

## Phase 4. Web 분석가 Workflow

### 변경

- Candidate 상세 `Flow review`
  - candidate IP로 필터된 Flow 표
  - Payload 특징과 현재 verdict
  - PCAP Payload preview
  - C2 + signature / BENIGN 라벨
- Analysis 상세 `All analysis flows`
  - Candidate 승격 여부와 무관한 전체 Flow 탐색
  - endpoint/direction/protocol/service-port/Payload 필터와 pagination
- `Payload signatures`
  - signature 상태, match guard, source provenance
  - 활성화/비활성화, 이름/설명/threshold 수정
- New Analysis 기본값
  - minimum score 20
  - minimum internal hosts 3

### 검증

- API body contract
- C2/benign mutation과 query invalidation
- 비활성화 및 오류 상태
- payload가 없는 Flow의 안전한 empty state

## Phase 5. 통합·운영 문서

- OpenAPI contract와 데이터 모델/아키텍처/운영 문서 갱신
- Python unit/integration, Worker, Go, Web lint/test/build
- synthetic PCAP에서 기존 detector 점수 회귀 확인
- signature false-positive tuning 절차와 monitor-only 운영 가이드 작성

## 완료 조건

`HGD-001`~`HGD-013`이 자동 테스트 또는 명시적 검증 증거로 모두 충족되고, 기존 성능
개선에서 분리한 compact Job metadata/참조형 queue 경계를 훼손하지 않아야 한다.
