# AI C2 Analysis 보안 경계

## 입력 경계

- raw PCAP을 모델 입력에 포함하지 않는다.
- Candidate의 결정론적 evidence와 Job Flow의 집계값만 Bundle로 변환한다. 개별 Flow와 raw packet/payload는 전달하지 않는다.
- Bundle은 보수적 UTF-8 byte estimator 기준 8,192 token 이하로 축소하며 64 KiB를 절대 상한으로 유지한다.
- `payload`, `payload_hex`, `payload_ascii`, `payload_preview`, `raw_payload`, `packet_hex`, `raw_packet_hex`, `pcap` 키는 metrics 중첩 깊이와 관계없이 제거한다.
- 캡처 문자열과 evidence 설명은 신뢰하지 않는 데이터다. FakeGateway fixture와 향후 system prompt는 이를 명령으로 실행하지 않는다.

## 출력 경계

- Pydantic의 strict enum/length/range schema를 통과한 JSON만 저장한다.
- supporting/counter/stable feature의 Evidence ID가 입력 Bundle에 실제 존재하는지 검증한다.
- Candidate IP가 입력과 다르면 거절한다.
- 능동 연결·스캔·공격을 뜻하는 `passive_only=false` action은 schema에서 거절한다.
- local model의 malformed JSON/schema는 1회만 repair하며 두 번째 실패 결과는 저장하지 않는다.
- prompt에는 captured string을 명령으로 실행하지 말라는 system rule과 schema를 Evidence 뒤의 trusted instruction으로 배치한다.

## 권한과 감사

- Run 생성/취소: ANALYST 이상
- Run/assessment 일반 조회: VIEWER 이상
- Evidence Bundle 조회: ANALYST 이상
- Run 생성/idempotent 재요청, 취소, Evidence Bundle 조회는 append-only 감사 이벤트를 기록한다.

## 격리

AI Run과 assessment는 기존 Analysis Job/Candidate와 별도 저장 객체다. terminal AI Run은 immutable이며 모델/validator/Queue 장애는 원본 Analysis Job을 변경하지 않는다. 기능 기본값은 비활성이다.

High-Recall 생성 후보는 허용된 Candidate 필드와 sanitize된 factor metrics만 AI Run snapshot에 보존한다. 원본 Flow, payload sample, raw packet은 snapshot에 포함하지 않는다.

## 재현성과 저장

- Bundle hash는 파생 metadata를 제외하고 key를 정렬한 canonical JSON의 SHA-256이다.
- 현재 bounded Bundle은 Assessment JSONB에 inline 저장한다.
- 64 KiB를 넘는 향후 artifact는 DB에 직접 넣지 않고 MinIO object reference로 저장하는 정책을 적용한다.
