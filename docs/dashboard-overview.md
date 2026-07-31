# Dashboard 운영 개요

## 목적

Dashboard는 단순 누적 숫자가 아니라 분석가가 접속 직후 다음 질문에 답할 수 있어야 한다.

1. 수집 인프라가 정상인가?
2. 지금 진행 중이거나 실패한 분석이 있는가?
3. 새로 발생한 위협과 우선 조사 대상은 무엇인가?
4. 최근 분석의 맥락으로 바로 이동할 수 있는가?

## 정보 구조

### 1. 핵심 운영 지표

- 온라인 센서: 저장된 상태와 `heartbeat_timeout_seconds`를 조회 시점에 함께 평가
- 주의 필요 센서: `OFFLINE + DEGRADED`
- 진행 중 분석: `WAITING_FOR_SENSOR`, `CAPTURING`, `UPLOADING`, `INGESTING`, `ANALYZING`
- 최근 24시간 완료/실패/부분 완료: `completed_at`이 현재부터 24시간 이내인 작업
- 분석 파이프라인: `WAITING_FOR_SENSOR`부터 `ANALYZING`까지 단계별 작업 수
- High / Critical 후보: 억제되지 않은 후보의 실제 severity 기준
- 최근 24시간 후보: 후보 `first_seen` 기준
- 드롭 패킷: 전체 센서의 누적 `dropped_packets`
- 센서 수집 품질: 센서별 수신·드롭 패킷, 드롭률, heartbeat, 최근 오류

기존 화면은 모든 `candidate_count`를 High/Critical로 표시했으므로 심각도 의미가 정확하지 않았다. 새 API는 저장된 Candidate severity를 직접 집계한다.

### 2. 위협 추세

- 최근 24개 정시 구간에 Candidate `first_seen`을 배치한다.
- 데이터가 없는 시간도 0으로 반환해 그래프 축이 흔들리지 않게 한다.
- 심각도 분포는 Critical, High, Medium, Low의 전체 비율을 비교한다.

### 3. 지금 확인할 항목

다음 범주에서 최대 8개를 보여준다. 한 범주의 항목이 많아도 다른 범주가 사라지지 않도록 센서 3개, 분석 3개, 후보 2개의 초기 슬롯을 보장하고 남는 슬롯을 추가 항목으로 채운다.

- 오프라인·성능 저하 센서
- 실패 또는 부분 완료된 최근 분석
- Critical 후보

각 항목은 센서·분석·후보 상세 화면으로 직접 연결한다.

### 4. 우선 조사 후보와 최근 분석

- Critical을 High보다 먼저 배치하고 같은 심각도에서는 점수가 높은 후보를 우선한다.
- 후보 목록은 최대 5개이며 IP, 점수, severity, 근거 수, 마지막 관측 시각만 반환한다.
- 최근 분석은 최대 5개이며 상태, Candidate 수, Packet/Flow 수, 생성 시각만 반환한다.
- Dashboard 응답에 전체 evidence, flow, detector 설정을 포함하지 않는다.

### 5. 분석 파이프라인과 센서 수집 품질

- 활성 분석을 센서 대기, 캡처, 업로드, 수집, 탐지 단계로 구분한다.
- `PARTIALLY_COMPLETED`는 성공으로 합치지 않고 별도의 주의 항목으로 표시한다.
- 센서 상태는 마지막 heartbeat가 설정된 timeout보다 오래되면 저장 상태가 `ONLINE`이어도 `OFFLINE`으로 평가한다.
- 드롭률은 `dropped_packets / (received_packets + dropped_packets) * 100`으로 계산한다.
- Dashboard에는 운영상 주의가 필요한 센서부터 최대 5개를 보여주며 전체 목록은 Sensors 화면으로 연결한다.

## 스토리보드

1. 분석가가 Dashboard에 접속한다.
2. 상단 지표에서 오프라인 센서와 실패 작업 존재 여부를 확인한다.
3. `지금 확인할 항목`에서 가장 긴급한 항목의 상세 화면으로 이동한다.
4. 운영 문제가 없다면 `우선 조사 후보`에서 Critical/High 후보를 조사한다.
5. 추세와 심각도 분포로 현재 이벤트가 일시적 증가인지 확인한다.
6. 필요하면 `새 분석` 또는 `PCAP 업로드`로 즉시 분석을 시작한다.

## API

`GET /api/v1/dashboard`

응답 영역:

- `fleet`
- `analyses`
- `candidates`
- `candidate_trend`
- `priority_candidates`
- `recent_analyses`
- `sensor_quality`
- `attention`
- `generated_at`

집계는 `Repository.list_candidate_sets()`를 사용해 Job별 Candidate N+1 조회를 피한다. 억제된 Candidate는 운영 위협 통계에서 제외한다.

현재 Candidate 저장 형식은 Job별 JSON 배열이므로 Dashboard 집계는 Candidate set 전체를 읽는다. 단기 운영 규모에서는 단일 repository 호출로 제한하지만, 데이터가 커지면 repository 전용 집계 메서드와 짧은 TTL 캐시 또는 Candidate 행 단위 정규화가 필요하다. 센서 데이터는 최신 heartbeat 스냅샷이므로 시간별 품질 추세로 해석하지 않는다.

## 반응형 동작

- 900px 이하에서 추세·심각도와 후보·분석 영역을 한 열로 전환한다.
- 600px 이하에서 지표 카드와 조치 목록을 한 열로 표시한다.
- 긴 IP, 작업명, 오류 메시지는 카드 내부에서 줄바꿈한다.
