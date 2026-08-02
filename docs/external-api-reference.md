# 외부 API 참조 (External API Reference)

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

### 센서 Enrollment & Registration (내부용)

다음 API는 외부 sensor agent에서 사용하며 클라이언트 코드에서는 직접 호출하지 않는다.

| Method | Path | Status | 설명 |
|--------|------|--------|------|
| `GET` | `/api/v1/sensor-enrollments` | 200 | Enrollment 목록 |
| `GET` | `/api/v1/sensor-enrollments/{id}` | 200 | Enrollment 상세 |
| `DELETE` | `/api/v1/sensor-enrollments/{id}` | 204 | Enrollment 취소 |
| `POST` | `/api/v1/sensors/register` | 201 | Sensor 등록 |
| `POST` | `/api/v1/sensors/{sensor_id}/credentials/rotate` | 200 | Credential 교체 |

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

**Filter**: `?status=active&min_score=40&severity=HIGH&candidate_ip=203.0.113.50`

---

### Allowlist (허용 목록)

| Method | Path | Status | 설명 |
|--------|------|--------|------|
| `GET` | `/api/v1/allowlist` | 200 | 현재 allowlist 조회 |
| `POST` | `/api/v1/allowlist` | 201 | 항목 추가 (IP/CIDR/fingerprint) |
| `DELETE` | `/api/v1/allowlist/{entry_id}` | 204 | 항목 삭제 |

**Request body (`AllowlistCreate`)**:

```jsonc
{
  "ip": null,                  // 특정 IP ( CIDR또는 fingerprint와 exclusive )
  "cidr": null,               // CIDR 범위
  "domain": null,              // 도메인 패턴
  "payload_fingerprint_sha256": null,  // payload SHA-256
  "fingerprint_algorithm": "SHA-256",
  "description": ""            // 이유/설명
}
```

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
  "active": true,              // 활성화 여부
  "description": "...",         // 설명
  "simhash_threshold": 3       // 구조적 매칭 해밍 거리 (1-6)
}
```

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
import requests
import time

BASE = "http://localhost:8000"
TOKEN = os.environ["C2HUNTER_API_TOKEN"]
headers = {"Authorization": f"Bearer {TOKEN}"}


# 1. 대시보드 상태 확인
resp = requests.get(f"{BASE}/api/v1/dashboard", headers=headers)
dashboard = resp.json()
print(f"Sensors: {dashboard['fleet']['online']}/{dashboard['fleet']['total']}")


# 2. PCPC업로드 분석 시작
with open("./suspicious.pcap", "rb") as f:
    files = [("file", ("analysis-job-1.pcap", f))]
    params = {"name": "suspicious.pcap", "filename": "analysis-job-1.pcap"}


job = post({BASE}/api/v1/pcap-analysis-jobs, ...).json()
print(f"Job ID: {job['id']}")

# 3. 상태 폴링 (최대 60초)
for _ in range(60):
    status = requests.get(f"{BASE}/api/v1/analysis-jobs/{job['id']}", headers=headers).json()
    if status['status'] in ('COMPLETED', 'PARTIALLY_COMPLETED', 'FAILED'):
        break

# 4. 후보 조회
candidates = requests.get(
    f"{BASE}/api/v1/analysis-jobs/{job['id']}/candidates",
    headers=headers
).json()


# Critical/High 우선 정렬
priority = sorted(
    candidates['items'],
    key=lambda c: {'CRITICAL': 0, 'HIGH': 1}.get(c['severity'], 2)
)
```
