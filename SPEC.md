# DDoS Botnet C2 Detection Platform 개발 명세서

## 1. 프로젝트 개요

### 1.1 프로젝트명

**DDoS Botnet C2 Detection Platform**

프로젝트 코드명은 `C2Hunter`로 사용한다.

### 1.2 배경

DDoS 봇넷에 감염된 여러 단말은 공격 명령 수신, 상태 보고, 헬스체크, 대상 정보 수신 등을 위해 C2(Command and Control) 서버와 통신한다.

개별 감염 단말의 트래픽만 분석하면 일반적인 인터넷 통신과 C2 통신을 구분하기 어렵지만, 여러 감염 단말의 트래픽을 동시에 비교하면 다음과 같은 공통 특성을 식별할 수 있다.

* 여러 단말이 동일한 외부 IP와 통신
* 일정한 주기로 반복되는 저용량 통신
* 여러 단말에서 비슷한 시간에 발생하는 동기화된 통신
* 특정 서버로부터 패킷을 수신한 직후 다수 단말이 공격 트래픽 발생
* 동일한 프로토콜, 포트, 패킷 크기 또는 페이로드 특징 사용
* 여러 센서에서 동일한 목적지 또는 동일한 통신 패턴 관찰

본 시스템은 이러한 상관관계를 분석하여 C2 후보 IP를 자동으로 식별하고, 탐지 근거와 관련 트래픽을 분석가에게 제공하는 것을 목적으로 한다.

---

# 2. 최종 Goal

다음 목표를 충족하는 운영 가능한 MVP를 구현한다.

> 복수의 Linux 트래픽 센서에서 미러링된 네트워크 트래픽을 수집하고, 수집된 트래픽의 방향성과 센서 간 공통 컨텍스트를 분석하여 DDoS 봇넷 C2 서버 후보 IP를 식별하는 분산형 분석 시스템을 개발한다.
>
> 사용자는 Web UI 또는 REST API에서 분석 조건을 지정해 분석을 실행할 수 있어야 하며, 분석 결과로 C2 후보 IP, 신뢰도 점수, 관련 감염 단말, 탐지 근거, 시간대별 통신 현황 및 관련 PCAP 파일을 확인하고 다운로드할 수 있어야 한다.
>
> 시스템은 최소 2개의 센서와 1개의 중앙 컨트롤 시스템 구성을 지원해야 하며, 100만 패킷 이상의 데이터를 메모리 고갈 없이 처리할 수 있어야 한다.
>
> 모든 주요 기능에는 자동화된 단위 테스트, 통합 테스트, End-to-End 테스트 및 성능 테스트가 포함되어야 한다. Codex는 테스트가 모두 통과할 때까지 구현, 실행, 오류 수정 과정을 반복해야 한다.

---

# 3. 시스템 범위

## 3.1 구현 범위

시스템은 다음 기능을 포함한다.

1. Linux 네트워크 인터페이스 트래픽 캡처
2. Inbound/Outbound 방향 구분
3. 복수 센서 관리
4. 센서 원격 제어
5. 분석 트리거 생성
6. 시간, 패킷 수, 필터 조건 기반 캡처
7. Flow 및 프로토콜 메타데이터 생성
8. 센서 간 트래픽 상관분석
9. C2 후보 IP 식별 및 점수화
10. 분석 결과 Web UI 제공
11. 관련 PCAP 검색 및 다운로드
12. 분석 이력 및 감사 로그 관리
13. 자동화된 기능·통합·성능 테스트
14. Docker Compose 기반 실행 환경
15. AI 기반 C2 후보 분석 및 인텔리전스 (MISP, Splunk, Mock artifact)
16. 분석가 정의 payload signature와 detector weight preset

## 3.2 MVP에서 제외되는 기능

다음 항목은 초기 MVP의 필수 범위에서 제외한다.

* TLS 암호화 트래픽 복호화
* 실제 공격 대상에 대한 능동 스캐닝
* C2 서버에 대한 접속 또는 명령 수행
* 봇넷 제거 또는 감염 단말 치료
* 완전한 머신러닝 기반 분류 모델 (신경망 등). Z-score 기반 인구 집단 이상 탐지(`ml_population_anomaly`)는 포함.
* 수십 Gbps 이상의 하드웨어 가속 패킷 처리
* Kubernetes 기반 배포
* 장기 보관용 빅데이터 클러스터

단, 향후 확장이 가능하도록 인터페이스를 분리한다.

---

# 4. 기본 시스템 구성

## 4.1 구성 요소

시스템은 다음 구성 요소로 분리한다.

| 구성 요소            | 역할                                          |
| ---------------- | ------------------------------------------- |
| Sensor Agent     | Linux 인터페이스에서 패킷을 수집하고 Flow 및 프로토콜 메타데이터 생성 |
| Controller API   | 센서 등록, 상태 관리, 분석 요청, 사용자 API 제공             |
| Analysis Worker  | 수집 데이터 상관분석 및 C2 후보 점수 계산                   |
| Metadata Storage | 센서, 작업, 분석 결과, 사용자 설정 저장                    |
| Flow Storage     | 대규모 Flow 및 이벤트 데이터 저장                       |
| Object Storage   | PCAP 파일 및 분석 산출물 저장                         |
| Web UI           | 센서, 분석 작업, 결과 및 PCAP 조회                     |
| Job Queue        | 캡처, 분석, PCAP 생성 등의 비동기 작업 관리                |

## 4.2 기본 배치 구조

최소 지원 구성은 다음과 같다.

```text
                       ┌──────────────────────┐
                       │      Web Browser     │
                       └──────────┬───────────┘
                                  │ HTTPS
                       ┌──────────▼───────────┐
                       │   Controller / API   │
                       └──────┬───────┬───────┘
                              │       │
                    ┌─────────▼─┐   ┌─▼────────────┐
                    │ Analysis  │   │ DB / Storage │
                    │ Workers   │   │ PCAP / Flow  │
                    └───────────┘   └──────────────┘
                              ▲
                    mTLS/gRPC │
               ┌──────────────┴──────────────┐
               │                             │
        ┌──────▼───────┐              ┌──────▼───────┐
        │   Sensor A   │              │   Sensor B   │
        │ IN/OUT Mirror│              │ IN/OUT Mirror│
        └──────────────┘              └──────────────┘
```

센서는 Controller에 대해 아웃바운드 방식으로 연결한다. Controller가 센서에 직접 접속해야만 동작하는 구조는 사용하지 않는다.

이 구조를 통해 센서가 NAT 또는 방화벽 내부에 있더라도 중앙 시스템과 통신할 수 있어야 한다.

---

# 5. 권장 기술 스택

특별한 저장소 제약이 없다면 다음 기술을 기본값으로 사용한다.

## 5.1 Sensor Agent

* 언어: Go 1.25
* 패킷 캡처:
  * Linux AF_PACKET
  * TPACKET_V3 사용 우선
  * 개발 및 테스트 환경에서는 libpcap 사용 허용
* 패킷 파싱: gopacket 또는 동일 수준 라이브러리
* Controller 통신: JSON/REST over HTTPS (mTLS 또는 bearer token)
* 인증: token + HMAC signature (mTLS는 옵션)
* 로컬 버퍼: 파일 기반 spool queue (`sensor/internal/spool`)
* 설정 형식: YAML
* 배포 산출물: `c2hunter-sensor` 바이너리, systemd unit

## 5.2 Controller 및 분석 시스템

* 언어: Python 3.12 이상
* API: FastAPI
* 데이터 검증: Pydantic
* 비동기 작업: Redis list queue + lease 기반 Worker (`sensor/worker/src/c2hunter_worker`)
* Queue/Cache: Redis
* 분석 처리: 표준 라이브러리 (statistics, ipaddress) + 분석 전용 모듈
* 메타데이터 DB: PostgreSQL ( psycopg 3 )
* Flow 저장소:
  * PostgreSQL (기본, analysis-flow-tables 스키마)
  * ClickHouse는 옵션 (대규모 프로덕션)
* PCAP/Object Storage:
  * MinIO
  * S3-compatible API
* AI Assist:
  * Local LLM Gateway (`ollama`, `openai-compatible`, 또는 `fake`)
  * 구조화된 출력 검증 (Pydantic schema)
  * MISP draft, Splunk SPL/DTM/MACB, Mock integration artifacts

## 5.3 Web UI

* React 19
* TypeScript
* Vite
* 서버 상태 관리: TanStack Query
* 라우팅: react-router-dom
* UI: native CSS (외부 컴포넌트 라이브러리 없음)
* 차트: SVG + native

## 5.4 실행 환경

* Docker
* Docker Compose
* Linux 우선 지원
* Makefile 또는 Taskfile 제공

각 의존성 버전은 구현 당시 안정 버전으로 고정하고 lock 파일을 저장소에 포함한다.

---

# 6. 트래픽 방향성 정의

## 6.1 방향 구분

각 센서는 캡처 소스별로 명시적인 방향을 설정할 수 있어야 한다.

지원 값:

```text
INBOUND
OUTBOUND
BIDIRECTIONAL
UNKNOWN
```

센서 설정 예:

```yaml
sensor:
  id: sensor-seoul-01
  name: Seoul Mirror Sensor 01

capture_sources:
  - interface: ens2f0
    direction: INBOUND
    bpf_filter: ""
  - interface: ens2f1
    direction: OUTBOUND
    bpf_filter: ""
```

## 6.2 방향성 제약사항

동일한 물리 인터페이스에서 미러된 패킷만으로 방향을 판별할 수 없는 환경에서는 다음 중 하나가 반드시 제공되어야 한다.

* Inbound와 Outbound별 인터페이스 분리
* VLAN ID와 방향 간 매핑
* 내부 네트워크 CIDR 목록
* 사용자 정의 BPF 또는 방향 분류 규칙

방향을 판별할 수 없는 경우 임의로 방향을 추측하지 않고 `UNKNOWN`으로 기록한다.

## 6.3 내부 단말 판별

Controller에는 내부 네트워크 범위를 설정할 수 있어야 한다.

```yaml
internal_networks:
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16
```

운영자는 사설 IP뿐 아니라 통신사업자 또는 기관이 사용하는 공인 IP 대역도 내부 네트워크로 등록할 수 있어야 한다.

---

# 7. Sensor Agent 요구사항

## 7.1 센서 등록

센서는 시작 시 Controller에 다음 정보를 등록한다.

* Sensor ID
* Sensor 이름
* Hostname
* Agent 버전
* 운영체제 및 커널 버전
* 인터페이스 목록
* 인터페이스 MAC 주소
* 설정된 방향
* 지원 기능
* 현재 시간
* 사용 가능한 디스크 공간
* 캡처 드롭 통계

Sensor ID는 전체 시스템에서 고유해야 한다.

## 7.2 Heartbeat

센서는 기본 10초 간격으로 Controller에 heartbeat를 전송한다.

포함 정보:

* 현재 상태
* CPU 및 메모리 사용량
* 디스크 사용량
* 캡처 중인 작업
* 수신 패킷 수
* 드롭 패킷 수
* Controller 전송 대기 데이터 크기
* 마지막 오류

센서 상태:

```text
ONLINE
OFFLINE
DEGRADED
CAPTURING
ERROR
```

## 7.3 캡처 방식

센서는 다음 캡처 종료 조건을 지원해야 한다.

* 지정된 시작·종료 시간
* 지정된 기간
* 최대 패킷 수
* 최대 바이트 수
* 사용자의 중지 명령
* 디스크 여유 공간 부족
* 작업 제한 시간 초과

여러 조건이 제공된 경우 가장 먼저 충족된 조건으로 캡처를 종료한다.

## 7.4 캡처 필터

다음 필터를 지원한다.

* BPF expression
* Source/Destination CIDR
* Source/Destination port
* TCP/UDP/ICMP
* IP version
* Inbound/Outbound 방향
* Payload 저장 여부
* 전체 PCAP 저장 여부

## 7.5 Flow 생성

센서는 패킷 전체를 Controller로 전송하는 대신 기본적으로 Flow 메타데이터를 생성한다.

Flow 키:

```text
sensor_id
direction
ip_version
source_ip
destination_ip
source_port
destination_port
transport_protocol
```

Flow 레코드는 최소 다음 필드를 포함한다.

* 시작 시간
* 종료 시간
* 패킷 수
* 전체 바이트
* 최소·최대·평균 패킷 크기
* TCP flags 통계
* 양방향 여부
* Payload 길이 통계
* 최초 Payload 해시
* 마지막 Payload 해시
* PCAP object reference
* 캡처 작업 ID

기본 Flow idle timeout은 60초로 한다. 설정으로 변경 가능해야 한다.

## 7.6 프로토콜 메타데이터

가능한 경우 다음 정보를 추출한다.

### DNS

* Query name
* Query type
* Response code
* Answer IP
* TTL
* TXT record 길이 및 해시
* 요청·응답 시간

### HTTP

* Method
* Host
* URI path
* User-Agent
* Status code
* Content-Length
* Body 자체는 기본적으로 저장하지 않음

### TLS

* SNI
* ALPN
* TLS version
* Cipher suite 목록
* ClientHello/ServerHello fingerprint
* 인증서 subject 및 issuer
* 인증서 SHA-256 fingerprint

### 기타

알 수 없는 프로토콜도 다음 특징을 기록한다.

* 최초 N바이트의 해시
* Payload 길이
* Payload entropy
* 패킷 크기 시퀀스
* 요청·응답 크기 비율

개인정보 및 민감 데이터 보호를 위해 실제 Payload 저장은 기본적으로 비활성화한다.

## 7.7 로컬 버퍼링

Controller 연결이 끊긴 경우 센서는 데이터를 로컬 디스크에 임시 저장해야 한다.

요구사항:

* 재연결 시 자동 재전송
* 중복 전송 방지를 위한 batch ID
* 최대 spool 크기 설정
* 오래된 데이터 삭제 정책
* 디스크 부족 시 경고
* 데이터 손실 여부 기록

---

# 8. Controller 요구사항

## 8.1 센서 관리

Controller는 다음 기능을 제공한다.

* 센서 목록 조회
* 센서 상세 상태 조회
* 센서 활성화/비활성화
* 센서 태그 관리
* 센서 그룹 관리
* 센서별 인터페이스 및 방향 조회
* 마지막 heartbeat 확인
* 센서 오류 및 패킷 드롭 확인

## 8.2 센서 그룹

복수 센서를 하나의 분석 그룹으로 관리할 수 있어야 한다.

예:

```text
Group: Seoul-Botnet-Analysis

- sensor-seoul-in-01
- sensor-seoul-out-01
- sensor-busan-01
```

분석 요청 시 개별 센서 또는 센서 그룹을 선택할 수 있어야 한다.

## 8.3 분석 작업 상태

분석 작업은 다음 상태를 가진다.

```text
CREATED
WAITING_FOR_SENSOR
CAPTURING
UPLOADING
INGESTING
ANALYZING
COMPLETED
PARTIALLY_COMPLETED
FAILED
CANCELLED
```

각 상태 전환 시간과 원인을 감사 로그에 기록한다.

## 8.4 작업 멱등성

분석 생성 API는 `idempotency_key`를 지원해야 한다.

동일한 키로 요청이 반복되면 중복 작업을 생성하지 않는다.

---

# 9. 분석 트리거

## 9.1 분석 요청 조건

사용자는 다음 조건을 지정할 수 있어야 한다.

* 분석 이름 (`name`)
* 멱등성 키 (`idempotency_key`)
* Sensor ID 또는 Sensor Group
* 분석 시작 시간
* 분석 종료 시간
* 모드 (`LIVE`, `HISTORICAL`, `REANALYSIS`, `PCAP_UPLOAD`)
* 실시간 캡처 기간
* 최대 패킷 수
* 최대 바이트 수
* Inbound/Outbound 방향
* BPF 필터
* 내부 네트워크 (필수)
* 분석 대상 프로토콜
* PCAP 저장 여부
* 분석 프로파일
* 최소 감염 단말 수
* C2 후보 최소 점수
* Detector 가중치 (실행별)
* ML 인구 집안 이상 탐지 활성화 여부

## 9.2 분석 요청 예

```json
{
  "name": "suspected-botnet-analysis-001",
  "idempotency_key": "suspected-botnet-001-20260815",
  "sensor_ids": ["sensor-a", "sensor-b"],
  "mode": "LIVE",
  "start_time": "2026-08-15T00:00:00Z",
  "end_time": "2026-08-15T00:05:00Z",
  "capture": {
    "duration_seconds": 300,
    "max_packets": 2000000,
    "directions": ["INBOUND", "OUTBOUND"],
    "protocols": ["TCP", "UDP"],
    "bpf_filter": "ip",
    "store_pcap": true
  },
  "analysis": {
    "profile": "ddos_botnet",
    "minimum_distinct_clients": 5,
    "minimum_candidate_score": 60,
    "command_correlation_window_seconds": 10,
    "periodicity_min_samples": 5,
    "well_known_port_max": 1023,
    "non_well_known_port_min_ratio": 0.75,
    "high_volume_bytes_threshold": 52428800,
    "high_volume_packet_threshold": 100000,
    "high_volume_penalty": 30,
    "tcp_session_gating_enabled": true,
    "detector_weights": {
      "common_destination": 1.0,
      "periodic_beacon": 1.5,
      "single_host_composite_beacon": 2.0
    },
    "ml_anomaly_enabled": false,
    "ml_anomaly_z_threshold": 3.5
  },
  "internal_networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
}
```

- `idempotency_key`로 동일 요청 중복 제출 방지.
- `mode=LIVE`는 실시간 캡처 후 분석, `HISTORICAL`는 저장된 데이터, `PCAP_UPLOAD`는 업로드 PCAP 분석.
- `internal_networks`는 필수이며 내부/외부 분류 기준.
- `detector_weights`는 분석가 가중치 (default 1.0, max 2.0). 특정 detector의 기여도를 1.5배~2.0배로 조정.
- `ml_anomaly_enabled=true` 시 Z-score 기반 인구 집단 이상 탐지 활성화.

## 9.3 과거 데이터 분석

실시간 캡처뿐 아니라 이미 저장된 시간 범위의 데이터를 다시 분석할 수 있어야 한다.

동일한 데이터에 분석 파라미터를 변경하여 재분석할 수 있어야 한다.

---

# 10. C2 탐지 로직

초기 버전은 규칙 및 통계 기반으로 구현한다. 분석 모듈은 각각 독립적인 detector로 작성한다.

각 detector는 공통 인터페이스를 구현한다.

```python
class Detector:
    name: str
    version: str

    def analyze(self, context: AnalysisContext) -> list[Evidence]:
        ...
```

구현된 built-in detector (12개):

| detector name                 | 이름 / 역할                                        |
| --------------------------- | --------------------------------------------- |
| `common_destination`        | 다수 단말 공통 목적지                             |
| `non_well_known_port`       | 비 WELL-KNOWN PORT 사용                      |
| `periodic_beacon`           | 주기적 Beacon                                |
| `single_host_composite_beacon` | 단일 호스트 composite beacon              |
| `analyst_payload_signature` | 분석가 정의 payload signature                 |
| `synchronized_communication` | 동기화된 통신                                 |
| `command_attack_correlation` | 명령 수신 후 공격 상관관계                          |
| `persistence_rarity`        | 장기 지속성 및 목적지 희귀성                       |
| `protocol_similarity` | 프로토콜·payload 유사성                       |
| `ml_population_anomaly`     | 인구 집단 이상 탐지 (통계)                     |
| `multi_sensor_context`      | 다중 센서 상관분석                                |
| `tcp_session_quality`       | TCP 세션 품질 지표 (SYN/ACK 등)              |

`analysis/scoring.py`의 `DETECTOR_NAMES`, `analysis/detectors.py`의 실제 detector 클래스와 1대1로 대응한다.

추가로 분석가는 `analysis.custom.py`에 정의된 `CustomDetector` 또는 `docs/custom-detectors.md`의 Python plugin contract를 통해 자기 정의 detector를 등록할 수 있다. custom detector는 `DETECTOR` 객체, `create_detector()` factory, 또는 `analyze(context)` 함수 중 하나로 export하며, `build_detector_registry`에 추가된다.

## 10.1 다수 단말 공통 목적지 탐지

동일한 외부 IP와 통신한 내부 단말 수를 계산한다.

주요 지표:

* 고유 내부 IP 수
* 전체 연결 수
* 센서 수
* 통신 지속 시간
* 단말별 평균 연결 횟수
* 단말 간 공통 포트 비율
* 단말 간 공통 Payload fingerprint 비율

동일 외부 IP에 연결한 내부 단말 수가 기준값을 넘으면 후보 점수를 부여한다.

단, DNS, NTP, CDN, 공개 클라우드 및 사용자 등록 allowlist는 감점 또는 제외한다.

## 10.2 비 WELL-KNOWN PORT 사용

C2는 자주 `80`, `443` 같은 잘 알려진 포트가 아닌 비표준 포트를 사용해 탐지를 회피한다. `non_well_known_port` detector는 다음 조건을 검사한다.

* 내부 단말이 `1024`보다 높은 포트로 외부 IP와 통신했는가
* 해당 포트가 잘 알려진 서비스 포트(`80`, `443`, `53`, `5353` 등)가 아닌가
* 관찰 횟수가 최소 기준 이상인가

## 10.3 주기적 Beacon 탐지

각 내부 단말과 외부 IP 간 통신 시간 간격을 분석한다.

계산 항목:

* Inter-arrival time
* 평균 간격
* 표준편차
* 변동계수
* 반복 횟수
* 자기상관
* 허용 jitter 범위
* 패킷 크기 반복성

다음 조건일수록 점수를 높인다.

* 통신 간격이 일정함
* 패킷 크기가 유사함
* 장시간 지속됨
* 여러 내부 단말에서 동일 주기가 관찰됨
* 서로 다른 센서에서 동일 패턴이 관찰됨

정확히 일정한 통신뿐 아니라 ±10~30% jitter가 포함된 패턴도 탐지할 수 있어야 한다.

## 10.4 단일 호스트 Composite Beacon

`periodic_beacon`은 단말이 여러 외부 IP로 주기적으로 통신하는 패턴을 포착한다. `single_host_composite_beacon`은 **단일 외부 IP**에 대한 **단일 내부 단말**이 주기적이라는 복합 신호를 포착한다.

* 단 하나의 호스트만 관찰되더라도 `single_host_composite_beacon`이 감점되지 않도록 composite score를 계산한다
* `periodicity_min_samples` 파라미터로 최소 반복 횟수를 설정한다

## 10.5 분석가 정의 Payload Signature

`analyst_payload_signature`는 등록된 payload signature 목록을 이용해 Flow의 payload 해시와 메타데이터를 매칭한다. signature는 `POST /api/v1/payload-signatures`로 등록되며(`controller/repositories.py`의 `save_payload_signature`가 저장), `GET /api/v1/payload-signatures`로 조회, `PATCH /api/v1/payload-signatures/{signature_id}`로 수정, `DELETE /api/v1/payload-signatures/{signature_id}`로 삭제된다.

매칭 조건:

* payload hash (`payload_hash`)
* protocol / port
* host (DNS query name 또는 HTTP Host)

매칭된 signature는 `description`과 `confidence`를 Evidence에 포함시킨다.

## 10.6 동기화된 통신 탐지

다수 내부 단말이 짧은 시간 범위 내에 동일한 외부 IP에 연결하는지 분석한다.

예:

```text
12:00:00.100 bot-01 -> C2
12:00:00.410 bot-02 -> C2
12:00:00.720 bot-03 -> C2
12:00:01.020 bot-04 -> C2
```

설정 가능한 synchronization window를 사용한다.

기본값:

```text
2초
```

반복적으로 동기화 이벤트가 발생하면 높은 점수를 부여한다.

## 10.7 명령 수신 후 공격 트래픽 상관분석

C2 후보로부터 다수 내부 단말에 작은 Inbound 패킷이 전달된 이후, 동일 단말들에서 공통된 Outbound 트래픽 증가가 발생하는지 확인한다.

분석 단계:

1. 외부 IP에서 내부 단말로 전달된 공통 이벤트 탐지
2. 지정된 시간 창 내 Outbound 트래픽 변화 측정
3. 여러 단말에서 동시에 발생한 트래픽 증가 확인
4. 공통 목적지 IP, 포트, 프로토콜 확인
5. 평상시 대비 패킷 수 또는 PPS 증가율 계산

기본 시간 창:

```text
명령 추정 이벤트 이후 1~30초
```

다음 패턴은 높은 신뢰도의 근거로 사용한다.

* C2 후보 → 다수 봇: 소량의 동기화된 통신
* 다수 봇 → 특정 대상: 대량의 UDP/TCP/ICMP 통신
* 동일한 목적지 포트 또는 패킷 크기
* 여러 센서에서 동일한 공격 시작 시점 관찰

## 10.8 저용량 지속 통신 탐지

다음 특성을 가진 통신을 탐지한다.

* 장시간 유지
* 주기적으로 1~수 개 패킷 전송
* 송수신 데이터 크기가 작음
* 외부 IP 변경이 적음
* 일반 사용자 트래픽과 비교해 목적지가 희귀함

`persistence_rarity`는 다음 항목을 검사한다.

* 통신 지속 시간 (최소 시간 이상)
* 관측된 flow 수
* 외부 IP가 전체 population에서 얼마나 희귀한지 (분모 대비 비율)

## 10.9 프로토콜 및 Payload 유사성

다수 단말에서 다음 항목이 동일하거나 유사한지 비교한다.

* Destination IP/port
* TLS fingerprint
* 인증서 fingerprint
* HTTP Host 및 URI 구조
* DNS query pattern
* TXT record 크기
* 최초 Payload hash
* 패킷 크기 시퀀스
* Request/response 크기 비율

Payload 원문 대신 해시와 통계값을 우선 사용한다.

## 10.10 ML 기반 인구 집단 이상 탐지

`ml_population_anomaly`는 전체 population의 통계적 기준(평균, 표준편차)을 이용해 외부 IP별 관측 횟수가 현저히 큰지를 계산한다.

* Z-score 기반 이상 탐지
* 최소 관측 수(`periodicity_min_samples`와 동일 파라미터) 이하인 후보는 제외
* 기준을 초과한 후보는 별도 Evidence를 기록

머신러닝 기반 classifier는 MVP에서는 사용하지 않는다. 향후 확장을 위해 detector interface를 분리해 두었다.

## 10.11 다중 센서 상관분석

동일한 IP 또는 통신 패턴이 복수 센서에서 관찰되는 경우 추가 점수를 부여한다.

상관분석 키 예:

```text
destination_ip
destination_port
protocol
payload_fingerprint
tls_fingerprint
dns_domain
time_bucket
```

센서 시계 오차를 고려하여 기본 ±2초의 허용 범위를 적용한다.

## 10.12 TCP 세션 품질 지표

`tcp_session_quality`는 다음 TCP 세션 메트릭을 계산한다.

* SYN/ACK 비율
* RST 비율
* 재전송 (retransmit) 비율
* TCP flag 조합 이상 (SYN flood / FIN-ACK 이상 순서 등)

해상도가 높은 C2 채널은 낮은 재전송률과 높은 SYN/ACK 비율을 보인다.

## 10.13 중복 패킷 제거

미러 구성에 따라 동일 패킷이 여러 인터페이스 또는 센서에서 중복 관찰될 수 있다.

다음 필드를 사용해 일정 시간 범위 내 중복 가능성을 판별한다.

* Source/Destination IP
* Source/Destination port
* Protocol
* IP ID
* TCP sequence number
* Payload length
* Payload hash
* Timestamp bucket

중복 패킷을 제거하더라도 어느 센서에서 관찰되었는지는 별도로 보존한다.

---

# 11. C2 후보 점수 모델

각 후보 IP는 0~100 사이 점수를 가진다. `analysis/scoring.py`의 `score_candidates`가 계산한다.

초기 기본 가중치는 detector type별 CAPS이다.

| detector type              | 최대 점수 |
| ------------------------ | ----: |
| `COMMON_DESTINATION`     |    20 |
| `PERIODIC_BEACON`        |    15 |
| `SYNCHRONIZED_COMMUNICATION` | 15 |
| `COMMAND_ATTACK_CORRELATION` | 25 |
| `MULTI_SENSOR_CONTEXT`   |    10 |
| `PROTOCOL_PAYLOAD_SIMILARITY` | 10 |
| `LOW_VOLUME_PERSISTENCE_RARITY` | 5 |
| `SINGLE_HOST_BEACON`     |    35 |
| `ANALYST_PAYLOAD_SIGNATURE` | 80 |
| `NON_WELL_KNOWN_PORT`    |    25 |
| `ML_POPULATION_ANOMALY`  |     5 |
| `TCP_SESSION_QUALITY`    |    15 |

각 evidence type마다 contributor의 raw_score가 CAPS로 clip되어 합산된다. 동일 type에서 다수 detector가 발화하면 가장 큰 raw_score만 유효한 것이 아니라 type별로 독립 누적된다 (CAPS 이하).

## 11.1 Detector 가중치

`detector_weights` (default 1.0, max 2.0)를 통해 특정 detector의 기여도를 조정할 수 있다. 가중치 2.0이면 CAPS의 2배까지 올라간다. `POST /api/v1/detector-weight-presets`로 실행별 가중치가 저장/복원된다.

## 11.2 감점 항목

| 항목                   | 감점       |
| -------------------- | --------- |
| 명시적 allowlist        | 후보 제외 (`AllowlistEntry.matches`가 참이면 candidate 자체 비활성화) |
| 단일 내부 단말에서만 관찰       | -10 또는 -20 (`SINGLE_HOST_BEACON` 있으면 -10, 없으면 -20) |
| 분석 표본 부족              | -20       |
| 공용 DNS/NTP 정책 일치     | -30       |
| CDN/cloud 정책 일치       | -20       |
| 대용량 endpoint 통신 (bytes/packets threshold 초과) | -30  |
| 대용량 TCP 세션 (adjustment 후 score cap)  | 조정 후 점수가 `high_volume_tcp_session_score_cap`(기본 20)을 초과하면 그 값으로 cap  |

`ANALYST_PAYLOAD_SIGNATURE`의 EXACT 매칭(`match_mode == "EXACT"`)은 위 감점/제외 적용에서 제외된다 (분석가가 직접 등록한 시그니처인 경우).

## 11.3 점수 구간

```text
80~100 CRITICAL
60~79  HIGH
40~59  MEDIUM
0~39   LOW
```

최종 점수는 `max(0, min(100, round(raw + adjustments)))`로 0~100 범위로 clamp된다.

점수와 함께 반드시 점수 산출 근거를 제공한다. 단순히 숫자만 반환해서는 안 된다. `Candidate.adjustments`에 `ScoreAdjustment(kind, points, explanation)`이 저장되며, 각 adjustment는 어떤 규칙이 얼마나 감점/보정을 했는지를 설명한다.

---

# 12. 분석 결과 데이터

각 C2 후보는 다음 정보를 포함한다.

```json
{
  "candidate_ip": "203.0.113.10",
  "score": 87,
  "severity": "CRITICAL",
  "first_seen": "2026-07-20T10:00:00Z",
  "last_seen": "2026-07-20T10:05:00Z",
  "protocols": [
    "TCP",
    "TLS"
  ],
  "ports": [
    443
  ],
  "distinct_internal_hosts": 42,
  "sensor_ids": [
    "sensor-a",
    "sensor-b"
  ],
  "evidence": [
    {
      "type": "PERIODIC_BEACON",
      "score": 14,
      "description": "42 hosts contacted the destination at approximately 30 second intervals."
    },
    {
      "type": "COMMAND_ATTACK_CORRELATION",
      "score": 24,
      "description": "Outbound UDP traffic increased within 3 seconds after synchronized inbound messages."
    }
  ],
  "related_pcap_objects": [],
  "related_attack_targets": [],
  "false_positive_notes": []
}
```

## 12.1 설명 가능성

모든 탐지 결과에는 분석가가 결과를 검증할 수 있는 설명이 있어야 한다.

최소 제공 정보:

* 어떤 단말들이 관련되었는가
* 어느 센서에서 관찰되었는가
* 어떤 시간에 발생했는가
* 어떤 탐지기가 점수를 부여했는가
* 각 탐지기의 입력 지표
* 점수와 신뢰도
* 오탐 가능성
* 관련 PCAP 위치

---

# 13. Web UI 요구사항

## 13.1 Dashboard

Dashboard에는 다음 정보를 표시한다.

* Online/Offline 센서 수
* 현재 캡처 중인 작업
* 최근 완료된 분석
* High/Critical C2 후보 수
* 센서별 패킷 수 및 드롭률
* 최근 24시간 C2 후보 추이

## 13.2 Sensor 화면

* 센서 목록
* 상태
* 마지막 heartbeat
* 인터페이스
* 방향
* 버전
* CPU/메모리/디스크
* 캡처 통계
* 오류 메시지

## 13.3 분석 생성 화면

다음 조건을 입력할 수 있어야 한다.

* 분석 이름
* 센서 또는 센서 그룹
* 실시간 또는 과거 데이터
* 기간
* 최대 패킷 수
* 방향
* BPF 필터
* PCAP 저장 여부
* 분석 프로파일
* 최소 C2 점수
* 최소 내부 단말 수

## 13.4 분석 진행 화면

* 현재 상태
* 단계별 진행률
* 수집 패킷 수
* 생성된 Flow 수
* 처리된 후보 IP 수
* 시작·경과 시간
* 센서별 상태
* 취소 버튼
* 오류 및 경고

## 13.5 결과 화면

결과 목록 필드:

* C2 후보 IP
* 점수
* 심각도
* 관련 내부 단말 수
* 센서 수
* 프로토콜 및 포트
* 최초·최종 관찰 시간
* 주요 탐지 근거

상세 화면:

* 시간대별 트래픽 차트
* 관련 내부 단말 목록
* 센서별 관찰 현황
* Beacon 주기 분석
* 명령·공격 상관관계 타임라인
* 관련 공격 대상
* 탐지 근거별 점수
* Flow 목록
* PCAP 다운로드

## 13.6 Allowlist 관리

사용자는 다음 항목을 allowlist로 등록할 수 있어야 한다.

* IP
* CIDR
* Domain suffix
* TLS fingerprint
* 인증서 fingerprint
* 설명
* 만료 시간

Allowlist에 의해 제외된 결과도 감사 목적으로 별도 통계에 기록한다.

## 13.7 AI C2 분석 화면

C2 후보의 상세 화면 옆에 AI 분석 패널을 표시한다.

* 분석 트리거: 후보 상세에서 "AI Analyze" 버튼
* 진행 상태: `QUEUED` → `RUNNING` → `SUCCEEDED` / `FAILED`
* 결과:
  - AI summary (Korean text, 구조화된)
  - verdict: `CONFIRMED_C2` / `LIKELY_FP` / `INCONCLUSIVE`
  - confidence: `HIGH` / `MEDIUM` / `LOW`
  - key_indicators (IP, 포, 프로토콜, 시그니처)
  - risk_factors (감점/고려 사유)
  - recommended_actions (단기 조치)
* Artifacts:
  - MISP draft (JSON)
  - Splunk SPL/DTM/MACB
  - Mock integration
* 재분석: AI summary가 아닌 후보 상태에 따라 "Re-analyze" 버튼
* 감사: 모든 AI 호출이 감사 로그에 기록 (token, prompt, artifact)

AI 분석은 비동기로 처리되며, 결과 저장까지 통상 30초~3분. `POST /analysis-jobs/{job_id}/ai-runs`로 run을 생성한 뒤 `GET /ai-runs/{run_id}`로 run 상태를, `GET /ai-assessments/{assessment_id}`로 assessment 결과를 폴링한다.

---

# 14. PCAP 저장 및 다운로드

## 14.1 저장 정책

PCAP 저장은 작업별로 활성화하거나 비활성화할 수 있어야 한다.

PCAP 파일은 다음 기준으로 회전한다.

* 최대 파일 크기
* 최대 시간
* 작업 종료
* 센서 재시작

기본값 예:

```text
파일 크기: 1GB
회전 시간: 5분
```

## 14.2 후보별 PCAP 추출

사용자는 전체 작업 PCAP뿐 아니라 특정 C2 후보와 관련된 패킷만 추출해 다운로드할 수 있어야 한다.

지원 필터:

* Candidate IP
* Internal host IP
* 시간 범위
* Port
* Protocol
* Direction
* Sensor

대규모 PCAP 추출은 비동기 작업으로 처리한다.

## 14.3 다운로드 보안

* 인증된 사용자만 다운로드 가능
* 다운로드 이력 기록
* 만료 시간이 있는 다운로드 URL 사용
* 경로 조작 방지
* Content-Disposition filename 검증
* 최대 다운로드 크기 제한
* 접근 권한 확인

---

# 15. API 요구사항

API prefix:

```text
/api/v1
```

주요 API:

```text
# Analysis jobs
POST   /analysis-jobs
GET    /analysis-jobs
GET    /analysis-jobs/{job_id}
PATCH  /analysis-jobs/{job_id}
DELETE /analysis-jobs/{job_id}
POST   /analysis-jobs/{job_id}/cancel
POST   /analysis-jobs/{job_id}/reanalyze
GET    /analysis-jobs/{job_id}/candidates
GET    /analysis-jobs/{job_id}/candidates/{candidate_id}
GET    /analysis-jobs/{job_id}/flows
GET    /analysis-jobs/{job_id}/flows/{flow_id}/payload-preview
GET    /analysis-jobs/{job_id}/flows/{flow_id}/detection-guidance
GET    /analysis-jobs/{job_id}/flow-labels
POST   /analysis-jobs/{job_id}/flow-labels

# PCAP upload analysis
POST   /pcap-analysis-jobs

# Candidate triage (분석 후 workflow)
GET    /candidates
GET    /candidates/{candidate_id}
PATCH  /candidates/{candidate_id}
DELETE /candidates/{candidate_id}
POST   /candidates/{candidate_id}/verdicts
POST   /candidates/{candidate_id}/actions
POST   /candidates/{candidate_id}/threat-intelligence/lookups
POST   /candidates/{candidate_id}/misp-exports
POST   /candidate-bulk-operations
GET    /integration-settings
PUT    /integration-settings

# Sensors
POST   /sensors/register
GET    /sensors
GET    /sensors/{sensor_id}
GET    /sensors/{sensor_id}/agent-config
POST   /sensors/{sensor_id}/heartbeat
POST   /sensors/{sensor_id}/flow-batches
PUT    /sensors/{sensor_id}/pcap-segments/{segment_id}
POST   /sensors/{sensor_id}/credentials/rotate
POST   /sensors/{sensor_id}/revoke
POST   /sensor-groups
GET    /sensor-groups
GET    /sensor-pcaps
GET    /sensor-pcaps/{segment_id}/download

# Sensor enrollments (admin)
GET    /sensor-enrollments
GET    /sensor-enrollments/{enrollment_id}
DELETE /sensor-enrollments/{enrollment_id}

# Dashboard
GET    /dashboard

# PCAP exports
POST   /pcap-exports
GET    /pcap-exports/{export_id}
GET    /pcap-exports/{export_id}/download

# Allowlist
POST   /allowlist
GET    /allowlist
DELETE /allowlist/{entry_id}

# Detector weight presets
GET    /detector-weight-presets
POST   /detector-weight-presets
PATCH  /detector-weight-presets/{preset_id}
DELETE /detector-weight-presets/{preset_id}

# Payload signatures
GET    /payload-signatures
PATCH  /payload-signatures/{signature_id}
DELETE /payload-signatures/{signature_id}

# AI C2 analysis (run -> assessment -> artifact lifecycle)
POST   /analysis-jobs/{job_id}/ai-runs
GET    /analysis-jobs/{job_id}/ai-runs
POST   /ai-runs/{run_id}/cancel
GET    /ai-runs/{run_id}
GET    /ai-runs/{run_id}/assessments
GET    /ai-assessments/{assessment_id}
GET    /ai-assessments/{assessment_id}/evidence-bundle
POST   /ai-assessments/{assessment_id}/artifacts/regenerate
POST   /ai-assessments/{assessment_id}/feedback
GET    /ai-assessments/{assessment_id}/feedback
GET    /ai-artifacts/{artifact_id}
POST   /ai-artifacts/{artifact_id}/approve
POST   /ai-artifacts/{artifact_id}/reject

# Health / observability
GET    /health
GET    /ready
GET    /metrics
```

`/pcap-analysis-jobs`은 업로드 PCAP 분석(`mode=PCAP_UPLOAD`)을 위한 별도 진입점이고, candidate triage route들은 분석 완료 후 triage·AI assessment·MISP 자동화 워크플로를 담당한다. `candidate` route의 `verdicts`·`actions`는 복수 형식이며, 후보별 PCAP 조회는 `pcap-exports`를 통해 수행한다.

OpenAPI 문서를 자동 생성한다.

모든 목록 API는 pagination, filtering 및 sorting을 지원한다.

---

# 16. 데이터 보관 정책

설정 가능한 보관 기간을 제공한다.

기본값:

| 데이터                 | 보관 기간 |
| ------------------- | ----: |
| Raw PCAP            |    7일 |
| Flow 데이터            |   30일 |
| 분석 결과               |  180일 |
| 감사 로그               |  365일 |
| Sensor heartbeat 상세 |   30일 |

보관 기간이 지난 데이터는 background cleanup job으로 삭제한다.

분석 결과가 참조하는 PCAP이 삭제된 경우 결과 화면에 명확하게 표시한다.

---

# 17. 시간 동기화 제약사항

센서 간 시간 차이가 크면 통신 동기화 및 명령 상관분석 결과가 부정확해진다.

운영 요구사항:

* 모든 센서는 NTP 또는 PTP를 사용해야 한다.
* 권장 센서 간 시간 오차는 100ms 이하이다.
* 허용 최대 오차는 기본 2초이다.
* 센서 heartbeat를 이용해 Controller와의 시간 차이를 측정한다.
* 허용 범위를 초과하면 센서를 `DEGRADED` 상태로 표시한다.
* 분석 결과에 시간 오차 경고를 포함한다.

---

# 18. 보안 요구사항

## 18.1 통신 보안

* Sensor ↔ Controller: JSON/REST over HTTPS (mTLS 또는 BEARER token + HMAC-signed envelope). `c2hunter-sensor/internal/transport/http.go`가 구현한다.
* Controller ↔ Web: HTTPS required. nginx (`web/nginx.conf`)이 TLS를终结한다.
* 내부 서비스 (Controller ↔ Worker, Worker ↔ Analysis): localhost 또는 Docker internal network, plaintext 허용 (isolated)
* PCAP: MinIO S3 (private endpoint), presigned URL (max 24h)
* Postgres/ClickHouse/Redis: local 또는 Docker internal, TLS optional
* Secrets: `.env` (gitignored), `c2hunter-sensor/environment` (mode 0640, root:c2hunter-sensor). Plaintext token은 log나 DB에 남지 않는다.
* Payload raw bytes: sensor `payload_preview_bytes: 0`이 default (비활성). 분석은 payload 해시와 통계값 기반 (`analysis/payload_features.py`)
* AI model: local Ollama 기본. external endpoint (openai-compatible, gpt-oss) 사용 시 Evidence가 out of host로 나가고 시작 시 warning이 출력된다. `C2HUNTER_AI_MODEL_API_KEY`는 env var에 저장된다.
* DB password/secret: 환경 변수 또는 secret manager (`.env`에 plaintext 기록 금지)
* Rate limit: `C2HUNTER_RATE_LIMIT_WINDOW_SECONDS`, `C2HUNTER_DEV_LOGIN_RATE_LIMIT`, `C2HUNTER_ANALYSIS_JOB_RATE_LIMIT`
* 인증서 만료 확인 및 revocation 지원
* API 입력값 검증

## 18.2 권한 (Role)

Role는 `controller/security.py`의 `Role` enum으로 정의된다.

```text
VIEWER  — candidate/flow/PCAP download read-only
ANALYST — allowlist, payload-signature, verdict, AI analysis management
ADMIN   — sensor enrollment, detector weight preset, AI model config, token management
```

Sensor는 dedicated sensor API로 접근하며 (`/api/v1/sensor-*`) 일반 human role과 분리된다.

- **Authentication**: static bearer token. SHA-256 digest가 env var에 저장 (e.g. `C2HUNTER_ANALYST_TOKEN_SHA256`). plaintext는 log나 DB에 남지 않는다.
- **Development login**: `C2HUNTER_DEV_LOGIN_ENABLED=true`로 일시 token을 발급 가능. TTL 최대 24h. production에서는 반드시 `false`.
- **Token binding**: `controller/security.py`의 `bind_role(token_digest)`가 token → role 매핑을 관리한다.
- **Rate limiting**: `C2HUNTER_RATE_LIMIT_WINDOW_SECONDS` per client IP (default 60s window).
- **Fail-closed auth**: `C2HUNTER_API_AUTH_REQUIRED=true`는 default. isolated test만 off.
- **Proxy trust**: `C2HUNTER_TRUSTED_PROXY_CIDRS`로 신뢰할 proxy만 허용.

## 18.3 감사 로그

다음 작업을 기록한다.

* 로그인
* 분석 생성 및 취소
* PCAP 다운로드
* Allowlist 변경
* Payload signature 변경
* Detector weight preset 변경
* AI assessment 실행·결과·artifact 승인
* Verdict 등록
* 센서 등록 및 해제
* 설정 변경
* 사용자 권한 변경
* 데이터 삭제

감사 로그에는 사용자, 시간, IP, 작업, 대상 ID 및 결과를 기록한다.

## 18.4 안전 제약

본 시스템은 방어적 분석 용도로만 동작해야 한다.

다음 기능을 구현하지 않는다.

* C2 후보에 능동 명령 전송
* C2 인증 우회
* 감염 단말 원격 제어
* 공격 재현
* 대상 시스템 취약점 공격
* 인터넷 전체 스캔

---

# 19. 성능 및 확장성 요구사항

## 19.1 필수 성능

기준 시스템:

```text
Controller:
- 8 vCPU
- 16GB RAM
- NVMe storage

Sensor:
- 4 vCPU
- 8GB RAM
- NVMe storage
```

필수 통과 조건:

1. 100만 패킷 이상의 PCAP을 OOM 없이 처리해야 한다.
2. 모든 패킷을 한 번에 메모리에 적재하지 않아야 한다.
3. 데이터 처리는 chunk 또는 streaming 방식으로 수행해야 한다.
4. 100만 패킷 분석을 기준 시스템에서 180초 이내 완료하는 것을 목표로 한다.
5. 분석 중 Controller 프로세스의 최대 메모리 사용량은 8GB 미만이어야 한다.
6. Sensor는 최소 100,000 PPS 입력 테스트에서 패킷 드롭률 1% 이하를 목표로 한다.
7. Flow 목록 조회 API의 일반 응답 시간은 5초 이하여야 한다.
8. 비동기 작업은 Controller 재시작 후 복구 가능해야 한다.

성능 목표를 달성하지 못하면 테스트 결과와 병목 원인을 문서화하고, 기능상 OOM 또는 데이터 손실이 없는 상태까지 최적화한다.

## 19.2 Backpressure

Controller 또는 네트워크가 느린 경우 Sensor는 다음 순서로 대응한다.

1. 메모리 queue
2. 로컬 디스크 spool
3. Flow batch 크기 조정
4. 전송 재시도
5. 최대 용량 초과 시 오래된 데이터 삭제 또는 캡처 중지

데이터가 삭제된 경우 조용히 무시하지 말고 손실량을 Controller에 보고한다.

## 19.3 환경 설정

### `c2hunter-sensor/config.yaml` (Sensor)

```yaml
controller:
  url: https://controller.example.com
sensor:
  name: edge-sensor
agent:
  state_file: /var/lib/c2hunter-sensor/state/agent.json
  config_poll_interval_seconds: 1
  capture_mode: on_demand  # or continuous
capture_sources: []
internal_networks: []
batch:
  max_items: 1000
  max_bytes: 1048576
capture:
  job_id: continuous
  packet_queue_size: 4096
  payload_preview_bytes: 0
spool:
  directory: /var/lib/c2hunter-sensor/spool
  max_bytes: 1073741824
  max_age_seconds: 86400
pcap:
  directory: /var/lib/c2hunter-sensor/pcap
  max_segment_bytes: 134217728
  max_segment_duration_seconds: 300
  max_disk_bytes: 1073741824
  queue_size: 4096
```

Sensor 인증은 `/etc/c2hunter-sensor/environment` (mode 0640, `root:c2hunter-sensor`)의 `C2HUNTER_ENROLLMENT_TOKEN`으로 처리한다.

### `.env.example` (Controller / development)

```bash
POSTGRES_DB=c2hunter
POSTGRES_USER=c2hunter
POSTGRES_PASSWORD=change-me-postgres
CLICKHOUSE_DB=c2hunter
CLICKHOUSE_USER=c2hunter
CLICKHOUSE_PASSWORD=change-me-clickhouse
MINIO_ROOT_USER=c2hunter-dev
MINIO_ROOT_PASSWORD=change-me-minio-at-least-8-characters
CONTROLLER_PORT=8000
WEB_PORT=8080
C2HUNTER_ENVIRONMENT=development
C2HUNTER_PCAP_UPLOAD_MAX_BYTES=524288000
C2HUNTER_PCAP_UPLOAD_MAX_PACKETS=2000000
C2HUNTER_DEV_LOGIN_ENABLED=true
C2HUNTER_DEV_TOKEN_TTL_SECONDS=28800
C2HUNTER_API_AUTH_REQUIRED=true
C2HUNTER_VIEWER_TOKEN_SHA256=
C2HUNTER_ANALYST_TOKEN_SHA256=
C2HUNTER_ADMIN_TOKEN_SHA256=
C2HUNTER_RATE_LIMIT_WINDOW_SECONDS=60
C2HUNTER_DEV_LOGIN_RATE_LIMIT=10
C2HUNTER_ENROLLMENT_CLAIM_RATE_LIMIT=10
C2HUNTER_ANALYSIS_JOB_RATE_LIMIT=30
C2HUNTER_TRUSTED_PROXY_CIDRS=172.30.0.10/32
C2HUNTER_AI_ANALYSIS_ENABLED=false
C2HUNTER_AI_MODEL_PROVIDER=fake
C2HUNTER_AI_MODEL_BASE_URL=http://host.docker.internal:11434
C2HUNTER_AI_MODEL_NAME=qwen3.6-agent:256k
C2HUNTER_AI_MODEL_API_KEY=
C2HUNTER_AI_MODEL_TIMEOUT_SECONDS=120
C2HUNTER_AI_MODEL_RETRIES=1
C2HUNTER_AI_MODEL_TEMPERATURE=0.1
C2HUNTER_AI_MODEL_CONTEXT_TOKENS=16384
C2HUNTER_AI_MODEL_MAX_OUTPUT_TOKENS=4096
C2HUNTER_AI_METRICS_PORT=9102
C2HUNTER_VIRUSTOTAL_API_KEY=
C2HUNTER_ABUSEIPDB_API_KEY=
C2HUNTER_THREAT_INTEL_TIMEOUT_SECONDS=10
C2HUNTER_THREAT_INTEL_REQUEST_DELAY_SECONDS=1
C2HUNTER_ABUSEIPDB_MAX_AGE_DAYS=90
C2HUNTER_MISP_URL=
```

Production에서는 `.env` 대신 secret manager (Vault, AWS Secrets Manager 등)에서 주입하고 `C2HUNTER_DEV_LOGIN_ENABLED=false`로 고정한다.

---

# 20. 오류 처리

모든 오류는 구조화된 error code를 사용한다.

예:

```json
{
  "error": {
    "code": "SENSOR_CAPTURE_FAILED",
    "message": "Unable to start packet capture on ens2f0",
    "details": {
      "sensor_id": "sensor-a",
      "interface": "ens2f0"
    }
  }
}
```

주요 오류 상황:

* 존재하지 않는 인터페이스
* 캡처 권한 부족
* Controller 연결 실패
* PCAP 업로드 실패
* 저장소 용량 부족
* Sensor 시간 오차
* 데이터 파싱 실패
* 분석 Worker 실패
* 분석 일부 센서 실패
* PCAP export 실패

일부 센서만 실패한 경우 가능한 데이터로 분석을 계속하고 상태를 `PARTIALLY_COMPLETED`로 기록한다.

---

# 21. 관측성

## 21.1 로그

모든 서비스는 JSON 구조화 로그를 사용한다.

필수 필드:

```text
timestamp
level
service
component
job_id
sensor_id
request_id
message
error
```

## 21.2 Metrics

Prometheus 형식의 `/metrics` endpoint를 제공한다.

주요 metrics:

* captured_packets_total
* dropped_packets_total
* generated_flows_total
* sensor_spool_bytes
* analysis_jobs_total
* analysis_duration_seconds
* candidate_c2_total
* pcap_storage_bytes
* queue_depth
* api_request_duration_seconds

## 21.3 Health check

* `/health`: 프로세스 생존 여부
* `/ready`: DB, Queue 및 Storage 연결을 포함한 요청 처리 가능 여부

---

# 22. 테스트 요구사항

테스트는 선택 사항이 아니라 프로젝트 완료를 위한 필수 조건이다.

## 22.1 단위 테스트

최소 테스트 대상:

* 방향 판별
* 내부/외부 IP 판별
* Flow key 생성
* Flow timeout
* 중복 패킷 판별
* Beacon 주기 계산
* Synchronization score
* Command/attack correlation
* Candidate score 계산
* Allowlist 감점
* 시간 오차 보정
* API 입력값 검증
* 보관 기간 계산
* PCAP export filter 생성

각 detector는 독립적인 테스트를 가져야 한다.

## 22.2 합성 트래픽 생성기

테스트용 트래픽 생성 모듈을 구현한다.

경로 예:

```text
tools/traffic-generator
```

다음 시나리오의 PCAP을 생성할 수 있어야 한다.

### Scenario A: Periodic Beacon

* 내부 단말 50개
* 동일한 C2 IP
* 30초 주기
* ±3초 jitter
* 동일한 포트
* 작은 요청·응답

예상 결과:

```text
C2 후보 점수 60 이상
PERIODIC_BEACON evidence 존재
내부 단말 수 50
```

### Scenario B: Synchronized Command and DDoS

* 내부 단말 100개
* 동일한 C2에서 명령 패킷 수신
* 1~3초 후 동일한 대상에 UDP burst
* 2개 센서에 트래픽 분산

예상 결과:

```text
C2 후보 점수 80 이상
COMMAND_ATTACK_CORRELATION evidence 존재
MULTI_SENSOR evidence 존재
공격 대상 IP 식별
```

### Scenario C: Benign DNS/NTP

* 다수 단말이 공용 DNS 및 NTP 서버와 통신
* 주기적인 통신 포함

예상 결과:

```text
C2 HIGH 또는 CRITICAL로 분류되지 않음
공용 서비스 감점 근거 존재
```

### Scenario D: CDN 트래픽

* 다수 단말이 동일한 CDN IP에 접속
* 다양한 Host/SNI 사용

예상 결과:

```text
단순 공통 목적지만으로 HIGH 판정하지 않음
```

### Scenario E: Sensor Duplicate

* 동일 패킷이 두 센서에서 중복 관찰

예상 결과:

```text
패킷 수 중복 제거
sensor observation은 2개로 유지
```

### Scenario F: Clock Skew

* Sensor A와 B의 시간 차이 3초

예상 결과:

```text
시간 오차 경고
센서 DEGRADED 표시
분석 결과에 신뢰도 저하 표시
```

### Scenario G: Partial Sensor Failure

* 분석 중 Sensor B 연결 중단

예상 결과:

```text
작업 PARTIALLY_COMPLETED
Sensor A 데이터 분석 완료
손실 및 실패 내역 표시
```

## 22.3 통합 테스트

Docker Compose 환경에서 다음 전체 흐름을 테스트한다.

1. Controller 실행
2. Sensor A/B 등록
3. 분석 작업 생성
4. Sensor 캡처 명령 수신
5. 합성 트래픽 입력
6. Flow 업로드
7. 분석 Worker 실행
8. C2 후보 생성
9. 결과 API 조회
10. PCAP export 생성
11. PCAP 다운로드
12. 감사 로그 확인

## 22.4 End-to-End 테스트

Playwright를 사용해 다음 UI 흐름을 테스트한다.

* 로그인
* 센서 상태 확인
* 새 분석 생성
* 분석 진행 상태 확인
* 결과 목록 조회
* C2 상세 조회
* PCAP export 요청
* Allowlist 추가
* 재분석 실행

## 22.5 성능 테스트

다음 테스트 스크립트를 제공한다.

```text
make benchmark-1m
```

테스트 내용:

* 최소 100만 패킷 PCAP 생성
* Ingestion 수행
* Flow 생성
* 전체 detector 수행
* 결과 저장
* 처리 시간 및 최대 메모리 측정
* 결과를 JSON과 Markdown으로 저장

결과 파일:

```text
artifacts/benchmark-1m.json
artifacts/benchmark-1m.md
```

## 22.6 장애 복구 테스트

다음 상황을 자동 테스트한다.

* Controller 재시작
* Redis 재시작
* Worker 강제 종료
* Sensor 네트워크 단절
* MinIO 일시 장애
* PostgreSQL 일시 장애
* 중복 batch 재전송

---

# 23. 테스트 품질 기준

* Backend 핵심 모듈 line coverage 80% 이상
* C2 detector 모듈 line coverage 90% 이상
* Sensor 핵심 Flow 처리 모듈 coverage 80% 이상
* 모든 API에 정상·오류 테스트 작성
* 고정된 seed를 사용해 테스트 재현성 보장
* 테스트는 외부 인터넷 연결 없이 실행 가능해야 함
* 테스트에서 실제 공인 C2 서버를 호출하지 않음
* 실제 운영 PCAP을 저장소에 포함하지 않음

Coverage 숫자만 채우기 위한 의미 없는 테스트를 작성하지 않는다.

---

# 24. 저장소 구조

다음 구조를 기본으로 사용한다.

```text
c2hunter/
├── README.md
├── SPEC.md
├── TASKS.md
├── IMPLEMENTATION_REPORT.md
├── ENVIRONMENT_STATUS.md
├── HANDOFF.md
├── REVIEW.md
├── REVIEW2.md
├── REVIEW3.md
├── REVIEW4.md
├── SETUP_NOTES.md
├── FINAL_RESOLUTION.md
├── FINAL_SETUP_NOTES.md
├── EXECUTION_GUIDANCE.md
├── ASSET-NOTES.md
├── AI_C2_ANALYSIS_SYSTEM.md
├── LICENSE
├── Makefile
├── docker-compose.yml
├── .env.example
├── .env (gitignored)
├── requirements.txt (Python pinned)
├── docs/
│   ├── architecture.md
│   ├── data-model.md
│   ├── detection-logic.md
│   ├── detection-adjustment-guidance.md
│   ├── deployment.md
│   ├── operations.md
│   ├── security.md
│   ├── ai-c2-analysis-api.md
│   ├── ai-c2-analysis-operations.md
│   ├── ai-c2-analysis-progress.md
│   ├── ai-c2-analysis-security.md
│   ├── candidate-triage-misp-automation.md
│   ├── custom-detectors.md
│   ├── dashboard-overview.md
│   ├── external-api-reference.md
│   ├── human-guided-detection-plan.md
│   ├── human-guided-detection.md
│   ├── performance-scaling-plan.md
│   ├── c2hunter-intro.html
│   ├── assets/
│   └── adr/
├── sensor/
│   ├── go.mod (module c2hunter/sensor)
│   ├── go.sum
│   ├── cmd/
│   ├── internal/
│   │   ├── agent/
│   │   ├── batch/
│   │   ├── capture/
│   │   ├── contract/
│   │   ├── direction/
│   │   ├── flow/
│   │   ├── flowbatch/
│   │   ├── interfaces/
│   │   ├── metadata/
│   │   ├── packet/
│   │   ├── payloadfeature/
│   │   ├── pcap/
│   │   ├── runtime/
│   │   ├── spool/
│   │   ├── telemetry/
│   │   └── transport/ (JSON/REST)
│   ├── worker/ (Python analysis worker, src/c2hunter_worker/)
│   └── config/
├── c2hunter-sensor/ (built binary + systemd unit, deployable)
├── controller/
│   ├── pyproject.toml (FastAPI, psycopg, redis, minio, httpx)
│   ├── src/c2hunter_controller/
│   │   ├── __init__.py
│   │   ├── app.py
│   │   ├── api_errors.py
│   │   ├── ai_analysis.py
│   │   ├── ai_artifacts.py
│   │   ├── ai_evaluation.py
│   │   ├── ai_evaluation_pipeline.py
│   │   ├── ai_feedback.py
│   │   ├── ai_gateway.py
│   │   ├── ai_queueing.py
│   │   ├── ai_worker.py
│   │   ├── allowlist_api.py
│   │   ├── capture_limits.py
│   │   ├── config.py
│   │   ├── detection_guidance.py
│   │   ├── detector_weight_presets_api.py
│   │   ├── flow_review.py
│   │   ├── healthcheck.py
│   │   ├── integrations.py
│   │   ├── jobs.py
│   │   ├── logging.py
│   │   ├── operations_api.py
│   │   ├── payload_signatures_api.py
│   │   ├── pcap.py
│   │   ├── production.py
│   │   ├── production_patch.py
│   │   ├── queueing.py
│   │   ├── repositories.py
│   │   ├── retention.py
│   │   ├── schemas.py
│   │   ├── security.py
│   │   ├── sensor_groups_api.py
│   │   └── storage.py
│   └── tests/
├── analysis/
│   ├── pyproject.toml
│   ├── src/c2hunter_analysis/
│   │   ├── __init__.py
│   │   ├── ai_candidates.py
│   │   ├── custom.py
│   │   ├── detectors.py
│   │   ├── domain.py
│   │   ├── high_volume_backtest.py
│   │   ├── ingestion.py
│   │   ├── pcap.py
│   │   ├── payload_features.py
│   │   ├── scoring.py
│   │   └── tcp_sessions.py
│   └── tests/
├── web/
│   ├── Dockerfile
│   ├── e2e/
│   ├── index.html
│   ├── nginx-main.conf
│   ├── nginx.conf
│   ├── package.json
│   ├── package-lock.json
│   ├── playwright.config.ts
│   ├── src/ (React 19 + TS + Vite)
│   │   ├── AnalysisConfiguration.tsx
│   │   ├── App.tsx
│   │   ├── api.ts
│   │   ├── main.tsx
│   │   └── styles.css
│   ├── tests/
│   └── vite.config.ts
├── deploy/
│   └── sensor/
├── scripts/
│   ├── build-sensor-tarball.sh
│   ├── install-sensor.sh
│   ├── controller.Dockerfile
│   ├── sensor.Dockerfile
│   ├── worker.Dockerfile
│   └── migrate-clickhouse-flow-layout.sh
├── tools/
│   ├── benchmark/
│   ├── traffic-generator/
│   └── check_tracked_elf.py
├── testdata/
│   ├── README.md
│   └── generated/
├── artifacts/
│   ├── ai-benchmark-report.json
│   ├── ai-evaluation-report.json
│   ├── ai-evaluation-report.md
│   ├── benchmark-1m.json
│   ├── benchmark-1m.md
│   ├── high-volume-policy-backtest.json
│   ├── high-volume-policy-backtest.md
│   ├── coverage-analysis.json
│   ├── c2hunter-sensor/
│   └── c2hunter-sensor-dev-linux-amd64.tar.gz
└── .github/
    └── workflows/
        └── ci.yml
```

---

# 25. 개발 단계

## Phase 1: 프로젝트 골격

* 저장소 디렉터리 생성
* Docker Compose 작성
* PostgreSQL, Redis, MinIO, ClickHouse 구성
* Controller health API 구현
* Sensor 기본 실행
* Web 기본 페이지
* 공통 로깅 및 설정 처리

완료 조건:

```text
docker compose up -d
make test
```

명령이 성공해야 한다.

## Phase 2: Sensor 및 수집

* 인터페이스 탐색
* 캡처 시작·중지
* 방향 설정
* Flow 생성
* PCAP 회전 저장
* Controller 등록
* Heartbeat
* 로컬 spool

## Phase 3: Controller 및 작업 관리

* 센서 관리 API
* 분석 작업 API
* 작업 상태 머신
* 센서 명령 전달
* Flow ingestion
* Object storage 연동

## Phase 4: 분석 엔진

* 공통 detector 인터페이스
* 12개 built-in detector (`common_destination`, `non_well_known_port`, `periodic_beacon`, `single_host_composite_beacon`, `analyst_payload_signature`, `synchronized_communication`, `command_attack_correlation`, `persistence_rarity`, `protocol_similarity`, `multi_sensor_context`, `ml_population_anomaly`, `tcp_session_quality`; `analysis/detectors.py`)
* Custom Python detector framework (`analysis/custom.py`)
* 점수 모델 (`analysis/scoring.py`, `CAPS`/`DETECTOR_NAMES`)
* Allowlist
* Detector weight presets
* AI C2 analysis (`controller/ai_analysis.py`, `controller/ai_gateway.py`, `controller/ai_artifacts.py`, `controller/ai_worker.py`)

## Phase 5: Web UI

* Dashboard
* Sensor 화면
* 분석 생성
* 분석 진행
* 후보 목록
* 후보 상세
* PCAP export
* Allowlist
* AI C2 분석 화면

## Phase 6: 테스트 및 최적화

* 합성 PCAP 생성 (`tools/traffic-generator`)
* 통합 테스트
* E2E 테스트 (Playwright)
* 100만 패킷 성능 테스트
* 장애 복구 테스트
* 문서화
* 보안 점검

---

# 26. Codex 자율 수행 규칙

Codex는 다음 규칙에 따라 프로젝트를 스스로 진행한다.

## 26.1 작업 시작

1. 본 명세서를 `SPEC.md`로 저장한다.
2. 전체 요구사항을 작업 단위로 분해한다.
3. 작업 목록을 `TASKS.md`에 작성한다.
4. 요구사항별 식별자를 부여한다.
5. 구현 순서와 의존성을 기록한다.
6. 명확한 제약이 없는 경우 본 문서의 기본 기술 선택을 따른다.
7. 사소한 구현 선택을 사용자에게 반복적으로 질문하지 않는다.

## 26.2 반복 수행 절차

각 작업에 대해 다음 과정을 반복한다.

```text
1. 요구사항 확인
2. 구현 계획 작성
3. 코드 구현
4. 단위 테스트 작성
5. 테스트 실행
6. Lint 및 정적 분석 실행
7. 실패 원인 수정
8. 전체 회귀 테스트 실행
9. TASKS.md 상태 갱신
10. 변경사항 문서화
```

테스트가 실패한 상태에서 다음 Phase로 진행하지 않는다.

## 26.3 오류 처리

의존성 설치나 빌드가 실패하면 다음 순서로 처리한다.

1. 로그에서 직접 원인 확인
2. 의존성 버전과 설정 확인
3. 최소 재현 테스트 작성
4. 수정
5. 관련 테스트 재실행
6. 전체 테스트 재실행

임시로 테스트를 비활성화하거나 assertion을 제거해 통과시키지 않는다.

## 26.4 구현 원칙

* 하드코딩된 IP, 경로, 비밀번호를 사용하지 않는다.
* 모든 설정은 환경변수 또는 설정 파일로 관리한다.
* 비밀값을 저장소에 커밋하지 않는다.
* `TODO`, `FIXME`, 빈 함수 또는 mock 반환값을 완료된 구현으로 간주하지 않는다.
* 테스트를 통과시키기 위한 가짜 C2 결과를 생성하지 않는다.
* 실제 분석 결과는 입력 데이터에서 계산해야 한다.
* 대규모 패킷을 한 번에 메모리에 적재하지 않는다.
* 모든 background job은 재시도와 오류 상태를 제공한다.
* 외부 서비스가 없어도 테스트가 재현 가능해야 한다.
* 공개 API 변경 시 OpenAPI 문서와 테스트를 함께 갱신한다.

## 26.5 진행 기록

`TASKS.md` 형식:

```markdown
## Phase 2: Sensor

- [x] SEN-001 Sensor registration
- [x] SEN-002 Heartbeat
- [ ] SEN-003 AF_PACKET capture
- [ ] SEN-004 Flow aggregation
- [ ] SEN-005 Local spool
```

중요한 아키텍처 결정은 ADR로 기록한다.

예:

```text
docs/adr/0001-use-grpc-between-sensor-controller.md
docs/adr/0002-store-flow-data-in-clickhouse.md
```

---

# 27. 필수 실행 명령

다음 명령을 제공해야 한다.

```bash
make setup
make build
make up
make down
make lint
make lint-security
make test
make test-unit
make test-integration
make test-e2e
make test-ai
make evaluate-ai
make generate-test-pcaps
make benchmark-1m
make benchmark-ai
make backtest-high-volume
make clean
```

추가로 `make sensor-agent`(센서 빌드·실행), `make test-coverage`(coverage 보고) 타깃을 제공한다. `lint`는 Python/Go/TypeScript lint, `lint-security`은 비밀정보·취약점 스캐닝을 수행한다.

`make test`는 최소한 단위 테스트와 핵심 통합 테스트를 수행해야 한다.

CI 환경에서는 다음 순서로 수행한다.

```text
lint
unit test
integration test
build
security scan
```

---

# 28. CI 요구사항

GitHub Actions 또는 동급 CI를 구성한다.

필수 검사:

* Go formatting 및 vet
* Python formatting 및 lint
* TypeScript lint
* 단위 테스트
* 통합 테스트
* Coverage
* Docker image build
* 의존성 취약점 검사
* 비밀정보 포함 여부 검사

Pull Request 또는 기본 브랜치 push 시 CI가 자동 실행되어야 한다.

---

# 29. 문서 요구사항

README에는 다음 내용을 포함한다.

* 프로젝트 목적
* 전체 아키텍처
* 빠른 시작
* 요구 사양
* 센서 설치 방법
* 인터페이스 및 방향 설정
* 분석 실행 예
* 결과 해석 방법
* 테스트 실행 방법
* 알려진 제한사항
* 문제 해결 방법

운영 문서에는 다음을 포함한다.

* 인증서 발급 및 갱신
* Sensor 추가·제거
* 디스크 용량 관리
* 데이터 보관 기간 설정
* 장애 복구
* 백업 및 복원
* 성능 튜닝
* 패킷 드롭 확인
* 시간 동기화 점검

---

# 30. Definition of Done

프로젝트는 다음 조건을 모두 만족해야 완료로 간주한다.

1. 2개 이상의 Sensor가 Controller에 등록된다.
2. Sensor별 Inbound/Outbound 방향을 설정할 수 있다.
3. Web UI에서 분석 조건을 입력하고 작업을 시작할 수 있다.
4. 시간 또는 최대 패킷 수 기준으로 캡처를 종료할 수 있다.
5. Flow 데이터와 선택적 PCAP이 중앙 시스템에 저장된다.
6. 복수 센서의 데이터를 동일 분석 컨텍스트로 통합한다.
7. 다수 단말 공통 목적지 탐지가 동작한다.
8. 주기적 Beacon 탐지가 동작한다.
9. 동기화된 통신 탐지가 동작한다.
10. 명령 수신 후 공격 트래픽 상관분석이 동작한다.
11. C2 후보에 0~100 점수와 탐지 근거가 제공된다.
12. 결과 화면에서 관련 단말과 센서를 확인할 수 있다.
13. 관련 PCAP을 조건에 따라 추출하고 다운로드할 수 있다.
14. Allowlist가 탐지 점수에 적용된다.
15. 합성된 정상 트래픽이 고위험 C2로 오탐되지 않는다.
16. 합성된 봇넷 시나리오가 기대 점수 이상으로 탐지된다.
17. 100만 패킷 성능 테스트가 OOM 없이 완료된다.
18. 단위·통합·E2E 테스트가 모두 통과한다.
19. 핵심 분석 모듈의 테스트 coverage가 기준을 충족한다.
20. Docker Compose 명령으로 전체 시스템을 실행할 수 있다.
21. 소스 저장소에 비밀번호나 인증서 개인키가 포함되지 않는다.
22. README와 운영 문서가 실제 구현과 일치한다.
23. 미완성 placeholder, 임시 mock, 비활성화된 핵심 테스트가 없다.
24. 최종 테스트 결과와 벤치마크 결과가 `artifacts/`에 저장된다.

---

# 31. 최종 검증 절차

Codex는 구현을 마친 뒤 다음 절차를 직접 수행한다.

```bash
make clean
make setup
make build
make lint
make test-unit
make test-integration
make generate-test-pcaps
make test-e2e
make benchmark-1m
docker compose up -d
```

이후 다음 항목을 확인한다.

```text
- 모든 Container 정상 상태
- Sensor A/B ONLINE
- 합성 C2 분석 작업 COMPLETED
- C2 후보 결과 생성
- 탐지 근거 표시
- 관련 PCAP export 성공
- 정상 DNS/NTP 시나리오가 HIGH 이상으로 탐지되지 않음
- 100만 패킷 테스트에서 OOM 없음
```

실패 항목이 있으면 원인을 수정하고 전체 검증 절차를 처음부터 다시 수행한다.

---

# 32. Codex 최종 보고서

작업 완료 시 다음 형식으로 `IMPLEMENTATION_REPORT.md`를 작성한다.

```markdown
# Implementation Report

## 구현 완료 기능

## 전체 아키텍처

## 사용 기술과 선택 이유

## C2 탐지 로직

## 테스트 결과

## Coverage 결과

## 100만 패킷 Benchmark 결과

## 알려진 제한사항

## 운영 시 주의사항

## 향후 개선 항목

## Definition of Done 검증표
```

완료되지 않은 항목이 있다면 완료했다고 주장하지 말고 다음 정보를 명확히 기록한다.

* 미완료 항목
* 실패 원인
* 현재 동작 범위
* 재현 방법
* 필요한 후속 작업

