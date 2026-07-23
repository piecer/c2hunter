# C2Hunter

C2Hunter is a defensive platform for correlating traffic observed by multiple Linux sensors and explaining likely DDoS botnet C2 candidates. It never connects to candidates, decrypts TLS, scans the Internet, or reproduces attacks.

## Architecture

```text
External Linux Sensor Agents -- outbound token-authenticated HTTPS --> Controller API --> PostgreSQL
                                                                    |  |-------> ClickHouse (flows)
Browser --> React UI ------------------------------------------------|  |-------> MinIO (PCAP)
                                                                    +--Redis--> Analysis worker
```

The control plane, flow store, object store, and queue are intentionally separate. Flow/packet tooling processes bounded chunks. See [architecture](docs/architecture.md), [data model](docs/data-model.md), and [detection logic](docs/detection-logic.md).

## Requirements

- 중앙 서버: Linux 또는 WSL2, Docker Engine 27+와 Compose v2.30+
- 외부 Sensor: systemd가 있는 Linux, AF_PACKET 지원 커널, 중앙 서버로의 outbound HTTPS
- Python 3.12, Go 1.25.12, Node.js 22.14.0 and npm 10+
- Development: 4 CPU, 8 GiB RAM, 20 GiB free disk
- Reference benchmark: 8 vCPU, 16 GiB RAM, NVMe

Dependencies and images are pinned in `pyproject.toml`, `go.mod`, `web/package-lock.json`, Dockerfiles, and `docker-compose.yml`.

## Quick start

```bash
cp .env.example .env
# Replace every change-me value in .env
make setup
make up
curl http://localhost:8000/api/v1/health
open http://localhost:8080
```

`C2HUNTER_DEV_LOGIN_ENABLED=true` permits the **Development login** UI only for local use. Set it to `false` outside an isolated workstation. `make down` stops services without deleting volumes.

## 외부 Sensor 설치와 인터페이스 방향

Sensor는 중앙 Docker Compose에 포함되지 않는다. 각 Linux 시스템에 독립 Agent로 설치하며, 모든 연결은 Sensor에서 Controller 방향으로 시작한다.

1. Web UI의 **External sensors → Enroll sensor**에서 Sensor 이름을 입력한다.
2. 인터페이스 행을 추가하고 각 인터페이스에 `INBOUND`, `OUTBOUND`, `BIDIRECTIONAL`, `UNKNOWN`, BPF, 활성 여부를 설정한다. 예를 들어 한 장비의 `ens2f0`은 `INBOUND`, `ens2f1`은 `OUTBOUND`로 설정할 수 있다.
3. 생성 직후 한 번만 표시되는 enrollment token과 설치 명령을 안전하게 복사한다.
4. 중앙 빌드 시스템에서 tarball을 만들고 외부 Sensor로 전송한다.

```bash
make sensor-agent
tar -xzf artifacts/c2hunter-sensor-dev-linux-amd64.tar.gz
cd c2hunter-sensor
sudo ./install-sensor.sh \
  --controller-url https://c2hunter.example.com \
  --enrollment-token '<ONE_TIME_TOKEN>'
sudo systemctl start c2hunter-sensor
sudo systemctl status c2hunter-sensor
```

Agent는 one-time token을 장기 Sensor credential로 교환해 mode `0600` state file에 저장하고, 중앙의 versioned desired configuration을 주기적으로 가져온다. 각 enabled 인터페이스는 독립 AF_PACKET→Flow→spool→upload pipeline으로 동작하므로 한 인터페이스 오류가 다른 인터페이스를 중단하지 않는다. 오류 시 Sensor는 `DEGRADED`와 인터페이스별 error/counter를 보고한다.

installer는 전용 non-root 사용자와 systemd hardening을 적용하고 binary에 `CAP_NET_RAW`/`CAP_NET_ADMIN`만 부여한다. root로 Agent를 직접 실행하지 않는다. 방향을 추론할 근거가 부족하면 `UNKNOWN`을 사용한다.

## Run an analysis

Log in, choose **New analysis**, select sensors, live/historical mode, duration, packet limit, directions, BPF, PCAP opt-in, profile, minimum score, and minimum host count. The equivalent API prefix is `/api/v1`; OpenAPI is at `http://localhost:8000/docs`.

Jobs move through `CREATED → WAITING_FOR_SENSOR → CAPTURING → UPLOADING → INGESTING → ANALYZING` and then a terminal status. Cancellation is available from the progress page. Reanalysis creates a new run against the original immutable dataset.

### Analysis history and offline PCAP

**Analysis history** lists sensor and uploaded-capture investigations together. An analyst can change only the display name and analyst note; source packets, time range, detector settings, evidence, and scores remain immutable. Terminal jobs (`COMPLETED`, `PARTIALLY_COMPLETED`, `FAILED`, or `CANCELLED`) can be deleted after confirmation. Deleting a job also removes its candidates and generated PCAP exports.

**Upload PCAP** accepts a classic PCAP or PCAPNG file and runs it through the same flow normalization, detectors, allowlist, and scoring path. Configure internal CIDRs so packet direction can be derived; ambiguous traffic remains `UNKNOWN`. Ethernet, raw IP, Linux cooked v1/v2, and loopback link types are supported. The defaults are 500 MiB and 2,000,000 timestamped packets and can be changed with `C2HUNTER_PCAP_UPLOAD_MAX_BYTES` and `C2HUNTER_PCAP_UPLOAD_MAX_PACKETS`.

The binary API is `POST /api/v1/pcap-analysis-jobs` with the file as the request body and analysis metadata as documented query parameters. It accepts `application/vnd.tcpdump.pcap`, `application/x-pcap`, `application/x-pcapng`, or `application/octet-stream`.

## Interpret results

Scores are `LOW 0–39`, `MEDIUM 40–59`, `HIGH 60–79`, and `CRITICAL 80–100`. A score is not an attribution verdict. Review evidence contributions, internal hosts, independent sensor observations, clock/loss warnings, command-to-attack timeline, and PCAP before escalation. DNS/NTP/CDN and allowlist matches reduce or suppress candidates.

Candidate detail supports asynchronous filtered PCAP export. Download URLs are expected to be authorized, audited, short-lived, and server-named.

## Tests and fixtures

```bash
make lint
make test                 # unit + core integration
make test-unit
make test-integration
make test-e2e             # deterministic Playwright API route fixture
make generate-test-pcaps  # Scenario A–G, fixed seed
make benchmark-1m         # 1,000,000 events, bounded chunks
```

Playwright fixtures exist only under `web/e2e`; production bundles contain no fake C2 result. Generator output is in `testdata/generated`; benchmark JSON/Markdown is in `artifacts/`.

## Required commands

`make setup`, `build`, `up`, `down`, `lint`, `test`, `test-unit`, `test-integration`, `test-e2e`, `generate-test-pcaps`, `benchmark-1m`, and `clean` are the supported command contract.

## Known limitations

- MVP uses rule/statistical evidence, not ML or attribution.
- TLS payloads are not decrypted; payload retention is disabled by default.
- Compose는 Controller, Worker, Web, PostgreSQL, Redis, ClickHouse, MinIO만 실행하는 단일 호스트 개발 토폴로지이며 production HA 구성이 아니다.
- The deterministic browser fixture validates UI behavior without a backend; it does not validate server authorization.
- AF_PACKET availability and packet-drop goals depend on host kernel, NIC, mirror quality, and privileges.
- Offline upload currently retains decoded packet bytes in the job dataset for filtered export; set conservative upload limits and retention for sensitive or high-volume captures.

## Troubleshooting

- `docker compose ... variable is required`: create `.env` and replace all required values.
- Unhealthy service: `docker compose ps` then `docker compose logs <service>`.
- UI cannot reach API: check `curl localhost:8000/api/v1/health` and the `web` proxy logs.
- Sensor missing: verify outbound DNS/TCP, certificate identity/expiry, NTP, and explicit interface direction.
- Drops/spool growth: inspect sensor heartbeat, disk capacity, BPF selectivity, batch size, and Controller readiness.
- Port conflict: change `CONTROLLER_PORT` or `WEB_PORT` in `.env`.

See [deployment](docs/deployment.md), [operations](docs/operations.md), and [security](docs/security.md).
