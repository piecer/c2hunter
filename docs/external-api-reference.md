# 외부 API 참조 (External API Reference)

## Candidate 자동 위협 인텔리전스

분석 결과에 Candidate가 저장되면 Controller는 구성된 외부 공급자를 점수 상위 순으로 자동
조회한다. `C2HUNTER_CANDIDATE_AUTO_ENRICHMENT_LIMIT`은 작업별 최대 후보 수이며 `0`이면
자동 조회를 끈다. 조회는 worker 수와 전역 in-flight queue capacity가 제한된 executor에서
실행되므로 외부 서비스 실패, timeout, backlog가 분석 작업의 `COMPLETED` 전이를 막지 않는다.
용량을 초과한 조회는 민감한 내부 정보 없이 `FAILED` resource로 기록된다.

Candidate의 `threat_intelligence`는 최신 조회 resource이며 detector 결과와 분리된다.

- `origin`: `AUTO` 또는 `MANUAL`
- `status`: `PENDING`, `COMPLETED`, `PARTIAL`, `FAILED`
- `providers`: `virustotal`, `abuseipdb`, `misp`의 공급자별 상태와 정규화 결과
- `summary`: VirusTotal 통계, AbuseIPDB confidence, MISP 검색 응답 최대 100건 내 attribute/event 개수
- `fetched_at`: 조회 시작 또는 완료 시각

Candidate 목록 endpoint인 `GET /api/v1/candidates`와
`GET /api/v1/analysis-jobs/{job_id}/candidates`는 기존 `threat_intelligence`와 함께 목록용
`ti_assessment` projection을 반환한다. UI 목록은 다음 compact projection만 표시한다.

- `status`: `NOT_CHECKED`, `PENDING`, `COMPLETED`, `PARTIAL`, `FAILED`
- `signal`: `UNKNOWN`, `INCOMPLETE`, `NO_SIGNAL`, `POSITIVE`
- `configured_providers`, `successful_providers`, `positive_providers`: provider coverage
- `virustotal_malicious`, `virustotal_suspicious`, `abuse_confidence_score`,
  `misp_event_count`: 목록 triage용 핵심 수치
- `fetched_at`: 최신 조회 시각

두 Candidate 목록 endpoint 모두 `ti_filter=POSITIVE|MISP_MATCH|INCOMPLETE`를 지원한다.
`sort=-ti_priority`는 MISP event 일치, 양성 provider 수, VirusTotal 악성/의심 수,
AbuseIPDB confidence, detector score, 최근 관측 순서의 설명 가능한 tuple로 정렬하고,
완전 동률이면 Candidate ID 오름차순으로 고정한다.
별도의 합산 위험 점수를 생성하거나 detector `score`를 변경하지 않는다. 기존 `score` 정렬은
문자열이 아니라 숫자값으로 수행한다.

`NO_SIGNAL`은 조회가 완료됐지만 알려진 외부 신호가 없다는 뜻이며 안전 또는 benign 판정이
아니다. `INCOMPLETE`, `PENDING`, `PARTIAL`, `FAILED`는 낮은 위험이 아니라 정보 부족이다.
전체 provider 응답과 오류 문맥은 API 호환성을 위해 목록과 Candidate 상세 endpoint의
`threat_intelligence`에 유지되지만, UI에서는 Candidate 상세에서만 펼쳐 표시한다.

`POST /api/v1/candidates/{candidate_id}/threat-intelligence/lookups`는 구성된 모든 공급자를
다시 조회해 `origin=MANUAL`인 새 resource를 저장한다. 일부 공급자가 실패하면 성공 결과를
버리지 않고 `PARTIAL`로 반환한다. 모든 연동이 비활성화된 경우 503
`THREAT_INTELLIGENCE_NOT_CONFIGURED`를 반환한다.

외부 TI 결과는 분석가 판정의 보조 근거다. 시스템은 결과만으로 Candidate를 자동 Confirm하지
않는다. `POST /api/v1/candidates/{candidate_id}/verdicts`의 `CONFIRMED_C2` 판정과
`POST /api/v1/candidates/{candidate_id}/misp-exports`의 MISP 쓰기는 기존 RBAC와 명시적 사용자
동작을 계속 요구한다.

C2Hunter Controller는 REST API를 제공하며, OpenAPI spec은 `http://localhost:8000/openapi.json` 또는 Swagger UI `http://localhost:8000/docs`에서 확인할 수 있다.

## 인증

모든 API는 Bearer token을 통해 인증한다. token은 SHA-256 digest 형태로 `.env`에 설정하고 역할을 부여한다.

```bash
# 토큰 생성 및 digest 계산
TOKEN="$(openssl rand -base64 32)"
printf '%s' "$TOKEN" | sha256sum
```

| 역할 | 권한 | 환경 변수 |
|------|------|-----------|
| `VIEWER` | 읽기 전용 | `C2HUNTER_VIEWER_TOKEN_SHA256` |
| `ANALYST` | 분석/수정/생성 | `C2HUNTER_ANALYST_TOKEN_SHA256` |
| `ADMIN` | 전역 관리 + sensor/detector 설정 | `C2HUNTER_ADMIN_TOKEN_SHA256` |

```http
GET /api/v1/candidates HTTP/1.1
Authorization: Bearer <YOUR_TOKEN>
```

### 개발 모드

`C2HUNTER_DEV_LOGIN_ENABLED=true`일 때 `POST /api/v1/dev-login`으로 메모리 세션 토큰을 발급할 수 있다. 프로덕션에서는 사용하지 않는다.

---

## API 엔드포인트 인벤토리

### Health check

| Method | Path | Status | 설명 |
|--------|------|--------|------|
| `GET` | `/api/v1/health` | 200 | 서버 상태 확인 |
| `GET` | `/api/v1/ready` | 200 | 준비 상태 (DB, Redis, ClickHouse 연결) |
| `GET` | `/api/v1/metrics` | 200 | Prometheus metrics |

### 대시보드 (Dashboard)

| Method | Path | Status | 설명 |
|--------|------|--------|------|
| `GET` | `/api/v1/dashboard` | 200 | 전체 운영 지점 요약 |

#### 응답 구조: GET /api/v1/dashboard

```jsonc
{
  "fleet": {                     // Fleet 상태
    "total": 5,                 // 총 sensor 수
    "online": 4,                // 온라인 수
    "offline": 1,               // 오프라인 수
    "degraded": 0               // 성능 저하 수
  },
  "analyses": {                 // 분석 작업 요약
    "active": 2,               // 진행 중
    "total": 15,               // 전체
    "completed_24h": 3,        // 24시간 완료
    "failed_24h": 0,           // 24시간 실패
    "partially_completed_24h": 1,
    "pipeline_stages": {       // 파이프라인 단계별 카운트
      "ANALYZING": 1,
      "CAPTURING": 1
    }
  },
  "candidates": {               // 후보 요약
    "total_24h": 8,             // 24시간 신규
    "severity_counts": {        // 심각도별 카운트
      "CRITICAL": 1,
      "HIGH": 3,
      "MEDIUM": 2,
      "LOW": 2
    }
  },
  "candidate_trend": {          // 시간대별 트렌드 (24시간)
    "2026-08-01T14:00:00Z": 1,
    "2026-08-01T15:00:00Z": 3
  },
  "priority_candidates": [...], // Critical/High 우선 후보 (max 5)
  "recent_analyses": [...],     // 최근 분석 (max 5)
  "sensor_quality": [...],      // sensor 품질 상태 (max 5)
  "attention": [...],           // 주목 필요 항목 (max 8)
  "generated_at": "2026-08-02T14:30:00Z"
}
```

---

### 센서 관리 (Sensors)

| Method | Path | Status | 설명 |
|--------|------|--------|------|
| `GET` | `/api/v1/sensors` | 200 | 모든 sensor 목록 |
| `GET` | `/api/v1/sensors/{sensor_id}` | 200 | Sensor 상세 정보 |
| `POST` | `/api/v1/sensor-groups` | 201 | Sensor grupo 생성 |
| `GET` | `/api/v1/sensor-groups` | 200 | 모든 sensor group 목록 |

#### 응답 필드 (Sensor object)

```jsonc
{
  "sensor_id": "...",           // UUID
  "name": "...",               // 표시명
  "status": "ONLINE",          // ONLINE/OFFLINE/DEGRADED
  "last_heartbeat_at": "...",   // 마지막 heartbeat 시각
  "received_packets": 0,        // 수신 패킷 수
  "dropped_packets": 0,         // 드롭 패킷 수
  "drop_rate_percent": 0.0      // 드롭률
}
```

### 센서 Enrollment & Registration (외부 Sensor Agent용)

다음 API는 외부 sensor agent에서 설치/등록/설정 폴링에 사용한다. ADMIN 토큰 필요.

| Method | Path | Status | 설명 |
|--------|------|--------|------|
| `POST` | `/api/v1/sensor-enrollments` | 201 | One-time enrollment 토큰 생성 |
| `GET` | `/api/v1/sensor-enrollments` | 200 | Enrollment 목록 조회 |
| `GET` | `/api/v1/sensor-enrollments/{id}` | 200 | Enrollment 상세 조회 |
| `DELETE` | `/api/v1/sensor-enrollments/{id}` | 204 | Enrollment 취소 |
| `POST` | `/api/v1/sensor-enrollments/{token}/claim` | 201 | Agent가 토큰 claim → 장기 credential 발급 |
| `POST` | `/api/v1/sensors/register` | 201 | Sensor agent 등록 (claim 후) |
| `GET` | `/api/v1/sensors/{sensor_id}/configuration` | 200 | Sensor 설정 조회 (CAPTURE 소스 + 내부 네트워크 등) |
| `PUT` | `/api/v1/sensors/{sensor_id}/configuration` | 200 | Sensor 설정 업데이트 (버전 충돌 체크) |
| `GET` | `/api/v1/sensors/{sensor_id}/agent-config` | 200 | Agent용 설정 폴링 응답 (`X-Sensor-Token` header 필요) |
| `POST` | `/api/v1/sensors/{sensor_id}/credentials/rotate` | 200 | Sensor credential 교체 |
| `POST` | `/api/v1/sensors/{sensor_id}/revoke` | 204 | Sensor 자격 증명 무효화 |

#### Agent 데이터 전송 (Sensor 내장 에이전트 전용)

Sensor agent가 Controller로 실시간 데이터를 업로드하는 엔드포인트이다. Bearer token이 아닌 `X-Sensor-Token` header를 통해 인증한다.

| Method | Path | Status | 설명 |
|--------|------|--------|------|
| `POST` | `/api/v1/sensors/{sensor_id}/heartbeat` | 200/202 | Heartbeat 보고 |
| `POST` | `/api/v1/sensors/{sensor_id}/flow-batches` | 202 | Flow batch 업로드 |
| `PUT` | `/api/v1/sensors/{sensor_id}/pcap-segments/{segment_id}` | 201 | PCAP 세그먼트 업로드 |
| `GET` | `/api/v1/sensor-pcaps` | 200 | 업로드된 PCAP 목록 |
| `GET` | `/api/v1/sensor-pcaps/{segment_id}/download` | 200 | 개별 PCAP 다운로드 |

#### Enrollment 토큰 생성 (예시)

```bash
# 1. 한 번용 enrollment 토큰 요청
POST /api/v1/sensor-enrollments
Authorization: Bearer <ADMIN_TOKEN>
Content-Type: application/json

{"name": "server-alpha"}

# 응답: {"enrollment_id": "...", "token": "<ONE_TIME_TOKEN>", "controller_url": "https://c2hunter.example.com"}

# 2. Agent side에서 토큰으로 long-lived credential claim
POST /api/v1/sensor-enrollments/<TOKEN>/claim
Content-Type: application/json

{
    "interfaces": [
        {
            "name": "ens2f0",
            "direction": "INBOUND",
            "bpf_filter": "",
            "pcap_retention_enabled": false,
            "active": true
        }
    ],
    "internal_networks": ["10.0.0.0/8"],
    "description": ""
}

# 응답: {"agent_token": "<LONG_LIVED_TOKEN>", ...}

# 3. Agent가 token으로 register
POST /api/v1/sensors/register
X-Sensor-Token: <LONG_LIVED_TOKEN>
Content-Type: application/json

{"os": "Linux", "kernel": "7.0.0-28-generic", ...}
```

**참고**: Sensor agent는 HTTP `X-Sensor-Token` header를 통해 인증하며 Bearer token으로는 접근하지 않는다.

---

### 분석 작업 (Analysis Jobs)

#### 분석 시작: 센서 기반 capture

```http
POST /api/v1/analysis-jobs HTTP/1.1
Authorization: Bearer <TOKEN>
Content-Type: application/json
```

**Request body (`AnalysisJobCreate`)**:

```jsonc
{
  "mode": "LIVE",              // LIVE 또는 HISTORICAL
  "sensor_ids": ["uuid-1"],    // 대상 sensor UUID 목록
  "analysis": {
    "directions": ["OUTBOUND"], // 방향 필터 (INBOUND/OUTBOUND/BIDIRECTIONAL)
    "bpf_filter": "",           // BPF 필터 문자열
    "capture_packets_limit": 500000, // 패킷 제한
    "duration_minutes": 10,     // 캡처 기간 (분)
    "pcap_retention_enabled": false,  // PCAP 보존 여부
    "minimum_candidate_score": 20,   // 최소 후보 점수
    "minimum_distinct_clients": 3,   // 최소 distinct client 수
    "periodicity_min_samples": 5,    // 주기성 검출 최소 샘플
    "detector_weights": {       //探测器가중치 (선택)
      "common_destination": 1.0,
      "periodic_beacon": 2.0
    },
    "ml_anomaly_enabled": false,
    "ml_anomaly_min_population": 30,
    "ml_anomaly_z_threshold": 3.5
  }
}
```

**응답**: `AnalysisJobCreate`에서 `flow_records`를 직접 전달할 경우 inline 분석 즉시 실행하고 결과를 반환한다. 그렇지 않으면 queue에排队되고 job ID가 반환된다.

#### PCAP 파일 업로드 분석

```http
POST /api/v1/pcap-analysis-jobs?name=MyPCAP&filename=test.pcap&internal_networks=10.0.0.0%2F8 HTTP/1.1
Authorization: Bearer <TOKEN>
Content-Type: application/vnd.tcpdump.pcap    // raw PCAP data
```

**Query parameters**:

| 파라미터 | 기본값 | 설명 |
|---------|--------|------|
| `name` | *(필수)* | 분석 표시명 |
| `filename` | *(필수)* | 파일명 |
| `internal_networks` | `10.0.0.0/8` | 내부 네트워크 CIDR 목록 (쉼표 분리) |
| `description` | `""` | 설명 |
| `idempotency_key` | - | 동일 키 재전송 방지 |
| `minimum_candidate_score` | `20` | 후보 점수 임계 (1-100) |
| `minimum_distinct_clients` | `3` | 최소 distinct client 수 |
| `detector_weights` | - | JSON 문자열 형태가 중 치 |
| `ml_anomaly_enabled` | `false` | ML 이상탐지 활성화 |

**업로드 제한**: `C2HUNTER_PCAP_UPLOAD_MAX_BYTES` (기본 500MB), `C2HUNTER_PCAP_UPLOAD_MAX_PACKETS` (기본 2,000,000)

#### 작업 관리

| Method | Path | Status | 설명 |
|--------|------|--------|------|
| `GET` | `/api/v1/analysis-jobs` | 200 | 분석 목록 (paginated) |
| `GET` | `/api/v1/analysis-jobs/{job_id}` | 200 | 작업 상세 |
| `PATCH` | `/api/v1/analysis-jobs/{job_id}` | 200 | 제목/설명 수정 |
| `POST` | `/api/v1/analysis-jobs/{job_id}/cancel` | 200 | 작업 취소 |
| `DELETE` | `/api/v1/analysis-jobs/{job_id}` | 204 | terminal 작업 삭제 |
| `POST` | `/api/v1/analysis-jobs/{job_id}/reanalyze` | 201 | 재분석 (새 job 생성) |

**Query**: `GET /api/v1/analysis-jobs?status=COMPLETED&sensor_ids=uuid&page=1&page_size=50`

#### Flow 조회

| Method | Path | Status | 설명 |
|--------|------|--------|------|
| `GET` | `/api/v1/analysis-jobs/{job_id}/flows` | 200 | Flow 목록 (Paginated) |
| `GET` | `/api/v1/analysis-jobs/{job_id}/flows/{flow_id}/payload-preview` | 200 | Payload 미리보기 (max 256 bytes) |

**Flow 응답 필드**:

```jsonc
{
  "flow_id": "...",            // deterministic hash
  "src_ip": "192.168.0.10",    // source IP
  "dst_ip": "203.0.113.50",   // destination IP (C2 candidate)
  "protocol": "TCP",           // L4 프로토콜
  "src_port": 54321,           // source port
  "dst_port": 8443,            // destination port
  "packets": 150,             // 패킷 수
  "bytes": 25600,             // 바이트 수
  "duration_seconds": 60,      // 지속 시간
  "first_seen": "...",         // 첫 관측 시각
  "last_seen": "...",          // 마지막 관측 시각
  "direction": "OUTBOUND",     // 방향
  "payload_hash_sha256": "...",  // first payload SHA-256
  "payload_entropy": 5.2,      // Shannon entropy
  "labels": [...]              // flow labels (C2/BENIGN)
}
```

**Flow 필터**: `?direction=OUTBOUND&protocol=TCP&dst_ip=...&src_port_range=1024-65535&page_size=100`

---

### 후보 (Candidates)

#### Candidate object 응답 구조

```jsonc
{
  "id": "...",                 // UUID
  "candidate_ip": "203.0.113.50",
  "score": 85,                // C2 suspicion score (0-100)
  "severity": "CRITICAL",     // LOW/MEDIUM/HIGH/CRITICAL
  "evidence_count": 7,        // 근거 수
  "hosts": ["10.0.1.23"],     // 관측된 internal host
  "first_seen": "...",         // 첫 관측 시각
  "last_seen": "...",          // 마지막 관측 시각
  "evidence": [                // 탐지 근거 (요약)
    {
      "type": "PERIODIC_BEACON",
      "detector": "periodic_beacon",
      "metrics": { "cv": 0.12, "sample_count": 37 }
    }
  ],
  "score_adjustments": [       // 점수 조정 내역
    {
      "type": "DETECTOR_WEIGHT_PERIODIC_BEACON",
      "points": 5,
      "explanation": "detector weight 적용: periodic_beacon x2.0"
    }
  ]
}
```

#### API 엔드포인트

| Method | Path | Status | 설명 |
|--------|------|--------|------|
| `GET` | `/api/v1/candidates` | 200 | 모든 후보 (paginated, filtered) |
| `GET` | `/api/v1/candidates/{id}` | 200 | Candidate 상세 |
| `PATCH` | `/api/v1/candidates/{id}` | 200 | 메모/명 표시 수정 |
| `DELETE` | `/api/v1/candidates/{id}` | 204 | 삭제 |
| `GET` | `/api/v1/analysis-jobs/{job_id}/candidates` | 200 | 특정 분석의 후보 |
| `GET` | `/api/v1/analysis-jobs/{job_id}/candidates/{id}` | 200 | 분석 기반 candidate |

**Candidate 목록 query parameters**:

- 공통: `page`, `page_size`, `severity`, `verdict`, `workflow_status`, `minimum_score`,
  `include_suppressed`, `sort`, `ti_filter`
- `sort`: `score`, `candidate_ip`, `first_seen`, `last_seen`, `severity`, `ti_priority`에
  `-` prefix를 붙이면 내림차순
- `ti_filter`: `POSITIVE`, `MISP_MATCH`, `INCOMPLETE`
- 예: `?minimum_score=40&severity=HIGH&workflow_status=NEEDS_REVIEW&ti_filter=POSITIVE&sort=-ti_priority`

---

### Allowlist (허용 목록)

| Method | Path | Status | 설명 |
|--------|------|--------|------|
| `GET` | `/api/v1/allowlist` | 200 | 현재 allowlist 조회 |
| `POST` | `/api/v1/allowlist` | 201 | 항목 추가 (IP/CIDR/domain/fingerprint/trusted service) |
| `DELETE` | `/api/v1/allowlist/{entry_id}` | 204 | 항목 삭제 |

**Request body (`AllowlistCreate`)**:

```jsonc
{
  "type": "IP",
  "value": "203.0.113.10",
  "description": "Temporary trusted infrastructure",
  "expires_at": "2026-08-20T01:30:00Z",
  "enabled": true
}
```

`type`은 `IP`, `CIDR`, `DOMAIN_SUFFIX`, `TLS_FINGERPRINT`,
`CERT_FINGERPRINT`, `TRUSTED_DNS`, `TRUSTED_NTP` 중 하나다. `expires_at`은 생략할 수
있지만, 지정할 때는 반드시 미래의 ISO 8601 절대 시각이어야 하며 `Z` 또는 UTC offset을
포함해야 한다. 예를 들어 `2026-08-20T10:30:00+09:00`은 저장·응답 시
`2026-08-20T01:30:00Z`에 해당하는 UTC 시각으로 정규화된다. timezone 없는
`2026-08-20T10:30`, 날짜만 있는 값, 이미 만료된 시각은 `422`로 거부된다.

---

### Payload 서명 (Payload Signatures)

분석가가 Flow C2로 라벨링 후 생성한 페이로드 시그니처를 관리한다.

| Method | Path | Status | 설명 |
|--------|------|--------|------|
| `GET` | `/api/v1/payload-signatures` | 200 | 모든 시그니처 목록 |
| `PATCH` | `/api/v1/payload-signatures/{id}` | 200 | 활성화/임계값 수정 |
| `DELETE` | `/api/v1/payload-signatures/{id}` | 204 | 삭제 |

**Request body (`PayloadSignatureUpdate`)**:

```jsonc
{
  "name": "sig-1",                      // 시그니처 이름 (선택)
  "description": "...",               // 설명 (선택)
  "enabled": true,                    // 활성화 여부 (선택)
  "length_tolerance_ratio": 0.1,     // 길이 허용 범위 비율 (0–1, 선택)
  "entropy_tolerance": 0.5,          // 엔트로피 허용 차이 (0–4, 선택)
  "simhash_max_distance": 6          // 구조적 매칭 최대 해밍 거리 (0–32, 선택)
}
```

> **주의**: 요청 body는 `extra="forbid"`이다. 알려진 필드가 아닌 값은 422 응답으로 거부된다. 최소 하나의 필드를 지정해야 한다.

---

### Flow 라벨링 (Flow Labels)

| Method | Path | Status | 설명 |
|--------|------|--------|------|
| `GET` | `/api/v1/analysis-jobs/{job_id}/flow-labels` | 200 | job의 flow label 목록 |
| `POST` | `/api/v1/analysis-jobs/{job_id}/flow-labels` | 201 | Flow에 C2/BENIGN 라벨 추가 |

**Request body (`FlowLabelCreate`)**:

```jsonc
{
  "flow_ids": ["hash-1", "hash-2"],  // 대상 flow ID 목록
  "verdict": "C2",                   // C2 또는 BENIGN
  "confidence": "HIGH",             // HIGH/MEDIUM/LOW
  "note": ""                        // 분석가 메모
}
```

---

### Detection Guidance (탐지 조정 가이드)

수동으로 Flow를 C2로 판정한 경우, 현재 데이터셋에서 탐지가 실패한 이유와 최적화 추천을 제공된다.

| Method | Path | Status | 설명 |
|--------|------|--------|------|
| `GET` | `/api/v1/analysis-jobs/{job_id}/flows/{flow_id}/detection-guidance` | 200 | 탐지 실패 원인 + 수정 권장 |

**응답 구조**:

```jsonc
{
  "conditions": [              // 실제 성립한 탐지 조건
    {
      "type": "COMMON_DESTINATION",
      "detector": "common_destination",
      "contribution": 12,
      "weighted_contribution": 15,
      "metrics": { ... }
    }
  ],
  "score_adjustments": [...],  // 감점 내역
  "current_score": 38,         // 현재 점수
  "minimum_candidate_score": 20, // 임계값
  "score_gap": -5,             // 부족 점수 (부호 포함)
  "recommendations": [          // 권장 변경안
    {
      "detector": "common_destination",
      "current_weight": 1.0,
      "suggested_weight": 1.75,
      "expected_score": 42,
      "risk_level": "MEDIUM"
    }
  ],
  "recommended_reanalysis": {  // 재분석 payload (예시)
    "detector_weights": {"common_destination": 1.75}
  },
  "warnings": [                // 주의 사항
    "동일 데이터셋에서 계산된 점수는 새 데이터 집합과는 다를 수 있습니다"
  ]
}
```

---

### Detector 가중치 Preset (Detector Weight Presets)

| Method | Path | Status | 설명 |
|--------|------|--------|------|
| `GET` | `/api/v1/detector-weight-presets` | 200 | preset 목록 |
| `POST` | `/api/v1/detector-weight-presets` | 201 | 새 preset 생성 |
| `PATCH` | `/api/v1/detector-weight-presets/{id}` | 200 | preset 이름/값 수정 |
| `DELETE` | `/api/v1/detector-weight-presets/{id}` | 204 | preset 삭제 |

**Request body (`DetectorWeightPresetCreate`)**:

```jsonc
{
  "name": "my-preset",
  "description": "",
  "detector_weights": {
    "common_destination": 1.5,
    "periodic_beacon": 2.0,
    "non_well_known_port": 1.0,
    // ...
  }
}
```

---

### PCAP export

| Method | Path | Status | 설명 |
|--------|------|--------|------|
| `POST` | `/api/v1/pcap-exports` | 201 | 필터 기반 PCAP export 생성 |
| `GET` | `/api/v1/pcap-exports/{id}` | 200 | Export 상태 조회 |
| `GET` | `/api/v1/pcap-exports/{id}/download` | 200 | Export 파일 다운로드 |

`POST`는 동기식으로 retained source를 해석하고 `COMPLETED` 또는 호환 가능한 `FAILED` export metadata를 반환한다. Upload 분석은 canonical capture, 완료된 LIVE 분석은 고정된 sensor-PCAP segment 집합, reanalysis는 parent provenance를 사용한다. Active LIVE 분석은 `409`, validation 실패는 `422`, rate limit 초과는 `429`다. 정상 설정에서 source scan/output 한도 도달은 `413`이 아니라 packet/block 경계의 `COMPLETED` partial export다. 필수 PCAP/PCAPNG header조차 수용하지 못하는 output 설정만 `413 PCAP_EXPORT_LIMIT_EXCEEDED`다.

기존 scalar 조건은 모두 AND다. `include_filters`와 `exclude_filters`는 각각 최대 20개 group이며, group 내부 active field는 AND, 각 group 목록은 OR로 평가한다. Nested `candidate_ip`는 exact IP/CIDR, `port`는 inferred external service port, `source_port`/`destination_port`는 transport port, `has_payload`는 aggregated flow가 아닌 개별 packet payload를 의미한다.

```jsonc
{
  "job_id": "analysis-id",
  "candidate_id": null,
  "internal_host_ip": "10.0.0.12",
  "protocol": "TCP",
  "include_filters": [
    {
      "candidate_ip": "203.0.113.0/24",
      "destination_port": 443,
      "direction": "OUTBOUND",
      "has_payload": true
    }
  ],
  "exclude_filters": []
}
```

성공 metadata에는 `source_job_id`, `source_capture_count`, `scanned_source_capture_count`, `omitted_source_capture_count`, `source_total_bytes`, `scanned_source_bytes`, `scanned_packet_count`, `output_byte_limit`, `source_scan_byte_limit`, `source_scan_packet_limit`, 검증 완료된 `source_manifest`, `matched_packet_count`, `exported_packet_count`, `omitted_packet_count`, `truncated`, `truncation_reasons`, `size_bytes`, artifact `sha256`, `capture_format`, server-generated `filename`이 포함된다. Stable reason은 `SOURCE_BYTE_LIMIT`, `SOURCE_PACKET_LIMIT`, `OUTPUT_BYTE_LIMIT`이다. Partial artifact의 filename에는 `-partial-` marker가 포함된다. 단일 link type은 `.pcap`, mixed interface/link type 또는 classic timestamp 범위 밖 packet은 `.pcapng`으로 생성되며 필요한 interface block만 packet과 함께 원자적으로 기록한다. Source 없음, scan ceiling이 첫 source/packet도 허용하지 않음, complete scan no-match, incomplete scan prefix no-match, matched packet 하나도 output에 들어가지 않는 경우는 각각 `FAILED/PCAP_SOURCE_UNAVAILABLE`, `FAILED/PCAP_SOURCE_SCAN_LIMIT_TOO_SMALL`, `FAILED/PCAP_NO_MATCH`, `FAILED/PCAP_SOURCE_SCAN_INCOMPLETE`, `FAILED/PCAP_OUTPUT_LIMIT_TOO_SMALL`로 저장되며 download는 `409 PCAP_NOT_AVAILABLE`을 반환한다. 저장된 source/artifact의 size 또는 SHA-256가 metadata와 다르면 각각 `409 PCAP_SOURCE_INTEGRITY_ERROR`/`409 PCAP_EXPORT_INTEGRITY_ERROR`를 반환한다. 동시 export admission 한도를 초과하면 `429 PCAP_EXPORT_BUSY`를 반환한다.

---

## 에러 응답

모든 API는 표준 오류 포맷을 반환한다:

```jsonc
{
  "error": {
    "type": "RATE_LIMITED",     // 에러 코드
    "message": "too many requests",
    "details": null             // 추가 정보
  }
}
```

| HTTP Status | 의미 |
|-------------|------|
| 400 | 잘못된 요청 (validation error) |
| 401 | 인증 실패 |
| 403 | 권한 부족 |
| 404 | 리소스 없음 |
| 409 | 충돌 상태 (ex: offline job에 inline flows 전달) |
| 429 | Rate limit 초과 |
| 500 | 서버 내부 에러 |

---

## OpenAPI spec

동적 spec과 interactive 테스트는 다음 URL에서 이용 가능하다:

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI JSON**: `http://localhost:8000/openapi.json`

CLI에서 spec을 추출하여 문서화 또는 코드 생성에 사용한다:

```bash
curl http://localhost:8000/openapi.json > c2hunter-openapi.json
```

## 외부 연동 예제 (Python)

```python
import os
import time
import requests

BASE = "http://localhost:8000"
TOKEN = os.environ["C2HUNTER_API_TOKEN"]
headers = {"Authorization": f"Bearer {TOKEN}"}


# 1. 대시보드 상태 확인
resp = requests.get(f"{BASE}/api/v1/dashboard", headers=headers)
dashboard = resp.json()
print(f"Sensors: {dashboard['fleet']['online']}/{dashboard['fleet']['total']}")


# 2. PCAP 업로드 분석 시작
with open("./suspicious.pcap", "rb") as f:
    response = requests.post(
        f"{BASE}/api/v1/pcap-analysis-jobs",
        headers=headers,
        data={"name": "suspiscious-traffic", "filename": "suspicious.pcap"},
        files={"file": ("suspicious.pcap", f)},
    )

job = response.json()
print(f"Job ID: {job['id']}, Status: {job['status']}")


# 3. 상태 폴링 (최대 60초)
for attempt in range(60):
    status_resp = requests.get(
        f"{BASE}/api/v1/analysis-jobs/{job['id']}",
        headers=headers
    )
    job_status = status_resp.json()
    if job_status['status'] in ('COMPLETED', 'PARTIALLY_COMPLETED', 'FAILED'):
        print(f"Analysis finished: {job_status['status']}")
        break
    time.sleep(1)


# 4. 후보 조회 (Paginated, Critical/High 우선 정렬)
candidates_resp = requests.get(
    f"{BASE}/api/v1/analysis-jobs/{job['id']}/candidates",
    headers=headers
)
candidates = candidates_resp.json().get('items', [])

priority = sorted(
    candidates,
    key=lambda c: ({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(c.get('severity', 'LOW'), 4), -c.get('score', 0))
)

for c in priority[:5]:
    print(f"  [{c['severity']}] {c['candidate_ip']} (score: {c['score']}, evidence: {c['evidence_count']})")


# 5. 특정 candidate 상세 조회 + 증거 확인
if priority:
    detail = requests.get(
        f"{BASE}/api/v1/candidates/{priority[0]['id']}",
        headers=headers
    ).json()
    print(f"\nTop threat: {detail['candidate_ip']}")
    for ev in detail.get('evidence', []):
        print(f"  - {ev['type']} from detector '{ev['detector']}' (contribution: {ev['contribution']})")


# 6. PCAP export 요청 (필터 기반)
export_resp = requests.post(
    f"{BASE}/api/v1/pcap-exports",
    headers={**headers, "Content-Type": "application/json"},
    json={
        "job_id": job['id'],
        "candidate_id": priority[0]['id'],
        "include_filters": [
            {"protocol": "TCP", "port": 443, "has_payload": True}
        ]
    }
)
export = export_resp.json()
print(f"\nExport ID: {export['id']}, Status: {export['status']}")

if export["status"] == "COMPLETED":
    download = requests.get(
        f"{BASE}/api/v1/pcap-exports/{export['id']}/download",
        headers=headers,
    )
    download.raise_for_status()
    with open(export["filename"], "wb") as f:
        f.write(download.content)
```

## Rate Limiting

API 요청은 time window 기반 rate limit이 적용된다. 제한 초과 시 `429 Too Many Requests`를 반환하며 `Retry-After` header에서 대기 시간을 확인할 수 있다.

| 엔드포인트 범주 | 기본 한도 |
|----------------|----------|
| Health / Metrics | Unlimited |
| Dashboard / Read | window 내 N회 |
| 분석 생성 (POST) | 제한적 (job 과부하 방지) |
| PCAP Export / Download | 별도 제한 |

window 크기와 한도는 `C2HUNTER_RATE_LIMIT_WINDOW_SECONDS`로 구성한다.
