# Deployment

## Development Compose

Prerequisites and version requirements are in `README.md`. Prepare secrets and validate the resolved topology before launch:

```bash
cp .env.example .env
chmod 600 .env
# edit .env; replace every change-me value
make setup
docker compose --env-file .env config --quiet
make build
make up
docker compose --env-file .env ps
curl -fsS http://localhost:8000/api/v1/health
curl -fsS http://localhost:8000/api/v1/ready
```

Compose starts PostgreSQL, Redis, ClickHouse, MinIO, Controller, Worker, and Web. Sensors run on external Linux systems and connect outbound to the Controller. Service dependencies use health checks. `make down` preserves named volumes. To intentionally erase local data, first back it up, then run `docker compose --env-file .env down -v` manually.

### Health check reference

| Service      | Command                                                    | Interval | Timeout | Retries |
|--------------|------------------------------------------------------------|----------|---------|---------|
| postgres     | `pg_isready -U $POSTGRES_USER -d $POSTGRES_DB`             | 10 s     | 5 s     | 10      |
| redis        | `redis-cli ping`                                           | 10 s     | 3 s     | 10      |
| clickhouse   | `wget http://127.0.0.1:8123/ping`                          | 10 s     | 5 s     | 15      |
| minio        | `curl -f http://127.0.0.1:9000/minio/health/live`          | 10 s     | 5 s     | 15      |
| controller   | `python -m c2hunter_controller.healthcheck`                | 10 s     | 5 s     | 15      |
| worker       | `python -m c2hunter_worker healthcheck --max-age 30`        | 15 s     | 5 s     | 5       |
| web          | `wget -q -O- http://127.0.0.1:8080/healthz`                | 10 s     | 3 s     | 10      |

### Controller environment variables (security)

The Controller reads these from `.env` via pydantic settings (`config.py:5-47`).
Values marked "SHA-256" must be 64-character lowercase hex digests — never plaintext tokens.

| Variable                              | Default             | Description                                       |
|---------------------------------------|---------------------|---------------------------------------------------|
| `C2HUNTER_ENVIRONMENT`                | `development`       | `test` disables auth defaults; otherwise auth is on |
| `C2HUNTER_DEV_LOGIN_ENABLED`          | `false` (config) / `true` (compose) | Enable dev-login endpoint                 |
| `C2HUNTER_API_AUTH_REQUIRED`          | `true` (non-test)   | Fail-closed authentication toggle                   |
| `C2HUNTER_VIEWER_TOKEN_SHA256`        | *(empty)*           | Static VIEWER bearer digest                         |
| `C2HUNTER_ANALYST_TOKEN_SHA256`       | *(empty)*           | Static ANALYST bearer digest                        |
| `C2HUNTER_ADMIN_TOKEN_SHA256`         | *(empty)*           | Static ADMIN bearer digest                          |
| `C2HUNTER_RATE_LIMIT_WINDOW_SECONDS`  | `60` (1–3600)       | Rate limiter window duration in seconds             |
| `C2HUNTER_DEV_LOGIN_RATE_LIMIT`       | `10`                | Max dev-login attempts per window per client IP     |
| `C2HUNTER_ENROLLMENT_CLAIM_RATE_LIMIT`| `10`                | Max enrollment claims per window per client IP      |
| `C2HUNTER_ANALYSIS_JOB_RATE_LIMIT`    | `30`                | Max analysis job creations per window per subject   |
| `C2HUNTER_AI_ANALYSIS_ENABLED`        | `false`             | Enable manual AI Runs; start Compose with `--profile ai` |
| `C2HUNTER_PCAP_UPLOAD_MAX_BYTES`      | `524288000` (500 MiB)| Maximum PCAP upload size                            |
| `C2HUNTER_PCAP_UPLOAD_MAX_PACKETS`    | `2000000`           | Maximum packets per PCAP upload                     |
| `C2HUNTER_PCAP_EXPORT_MAX_BYTES`      | upload byte limit   | Maximum serialized filtered PCAP/PCAPNG prefix      |
| `C2HUNTER_PCAP_EXPORT_SCAN_MAX_BYTES` | upload byte limit   | Maximum retained source bytes scanned per export    |
| `C2HUNTER_PCAP_EXPORT_SCAN_MAX_PACKETS` | upload packet limit | Maximum complete source packets scanned per export |
| `C2HUNTER_PCAP_EXPORT_MAX_CONCURRENT` | `1`                 | Maximum synchronous exports executing concurrently  |

### Candidate 외부 검증 및 MISP 연동

Candidate가 생성되면 점수 상위 N개를 대상으로 구성된 VirusTotal, AbuseIPDB, MISP
attribute 검색을 bounded worker에서 자동 실행한다. 외부 서비스 지연·rate limit·부분 장애는
분석 완료를 막지 않으며 공급자별 상태와 성공 결과를 함께 보존한다. Candidate 상세 화면은
자동/수동 조회 여부, 최근 조회 시각, 공급자별 근거를 판정 폼 옆에 표시한다. 분석가는 필요하면
같은 화면에서 최신 정보로 다시 조회할 수 있다.

외부 평판은 detector의 네트워크 행위 근거를 보강할 뿐 Candidate를 자동으로
`CONFIRMED_C2` 또는 `FALSE_POSITIVE`로 판정하지 않는다. 판정은 ANALYST의 명시적 동작이며,
MISP Event에 `ip-src` attribute를 쓰는 작업도 `CONFIRMED_C2` 판정 후 ADMIN이 명시적으로
실행해야 한다. 판정 이력, TI 조회, MISP 전송 성공·실패 이력은 detector Candidate JSON과
분리된 감사 resource로 보존되고 Candidate 조회 시 합성된다. `FALSE_POSITIVE` 판정은 detector
결과를 숨기거나 Allowlist에 자동 등록하지 않으며, 영구 억제는 별도 Allowlist 작업으로 수행한다.

| Variable | Default | Description |
|----------|---------|-------------|
| `C2HUNTER_VIRUSTOTAL_API_KEY` | *(empty)* | VirusTotal v3 API key; empty disables provider |
| `C2HUNTER_ABUSEIPDB_API_KEY` | *(empty)* | AbuseIPDB v2 API key; empty disables provider |
| `C2HUNTER_THREAT_INTEL_TIMEOUT_SECONDS` | `10` | Provider request timeout, 1–30 seconds |
| `C2HUNTER_ABUSEIPDB_MAX_AGE_DAYS` | `90` | AbuseIPDB report lookback, 1–365 days |
| `C2HUNTER_CANDIDATE_AUTO_ENRICHMENT_LIMIT` | `20` | Automatically enrich the highest-scoring N candidates per job; `0` disables automatic lookup |
| `C2HUNTER_CANDIDATE_AUTO_ENRICHMENT_WORKERS` | `4` | Bounded automatic lookup worker count, 1–16 |
| `C2HUNTER_CANDIDATE_AUTO_ENRICHMENT_QUEUE_CAPACITY` | `200` | Global automatic lookups allowed in flight; overflow is recorded as failed without blocking analysis |
| `C2HUNTER_MISP_URL` | *(empty)* | MISP base URL; empty disables lookup and export |
| `C2HUNTER_MISP_API_KEY` | *(empty)* | MISP automation/API key |
| `C2HUNTER_MISP_DEFAULT_EVENT_ID` | *(empty)* | Optional default Event ID; UI input overrides it |
| `C2HUNTER_MISP_VERIFY_TLS` | `true` | Verify the MISP server certificate |

Candidate 목록은 자동 조회 결과를 compact External TI 요약으로 표시한다. MISP 일치,
VirusTotal 악성/의심 수, AbuseIPDB confidence, provider coverage를 detector score와 분리해서
보여준다. `외부 신호 없음`은 안전 판정이 아니며, 조회 중·부분 완료·실패는 정보 부족으로
처리한다. 외부 TI 우선 정렬도 자동 verdict 또는 자동 Confirm을 수행하지 않는다.

운영 환경에서는 API 키를 `.env`, 이미지, Git에 저장하지 말고 secret manager에서 주입한다.
외부 API quota에 맞게 자동 조회 제한과 worker 수를 조정하고, 자동 조회를 원하지 않으면
`C2HUNTER_CANDIDATE_AUTO_ENRICHMENT_LIMIT=0`으로 설정한다. MISP 계정은 attribute 검색과
대상 Event에 attribute를 추가할 수 있는 최소 권한만 부여한다. MISP 전송은
동일 Candidate IP/Event 조합의 성공 이력을 확인해 중복 호출을 막으며, false-positive 또는
미판정 Candidate는 전송할 수 없다. 판정과 TI 조회는 ANALYST 이상, MISP 전송은 ADMIN만
호출할 수 있다. `C2HUNTER_MISP_VERIFY_TLS=false`는 신뢰 가능한 격리
개발망 외에는 사용하지 않는다.

## Certificates

Development certificates must be generated locally and ignored by Git. A minimal internal-CA workflow is:

```bash
umask 077
mkdir -p .runtime/pki
openssl genpkey -algorithm ED25519 -out .runtime/pki/ca.key
openssl req -x509 -new -key .runtime/pki/ca.key -out .runtime/pki/ca.crt -days 365 -subj '/CN=C2Hunter Development CA'
openssl genpkey -algorithm ED25519 -out .runtime/pki/sensor-a.key
openssl req -new -key .runtime/pki/sensor-a.key -out .runtime/pki/sensor-a.csr -subj '/CN=sensor-a/O=C2Hunter Sensors'
openssl x509 -req -in .runtime/pki/sensor-a.csr -CA .runtime/pki/ca.crt -CAkey .runtime/pki/ca.key -CAcreateserial -out .runtime/pki/sensor-a.crt -days 30
openssl verify -CAfile .runtime/pki/ca.crt .runtime/pki/sensor-a.crt
```

Repeat with a unique key and identity per sensor. In production, use the organization's CA or secret manager, SANs and Extended Key Usage, mount keys read-only, and keep the CA key offline. Rotate before expiry by issuing a new certificate, deploying it, confirming reconnect, and revoking the old serial. Never bake keys into images.

## Production boundary

Compose is a development/single-host artifact. Before production:

1. Terminate HTTPS at a maintained reverse proxy; disable development login. For offline analysis, configure that proxy to accept at least 500 MiB request bodies and allow at least 10 minutes for upload processing. Configure `C2HUNTER_TRUSTED_PROXY_CIDRS` with only the immediate proxy CIDRs; forwarded client headers from all other peers are ignored.
2. Require HTTPS for Sensor→Controller requests and protect the enrollment/agent token at rest and in transit. Sensors send it in `X-Sensor-Token`, not the human Bearer-token RBAC header. Remote `http://` Controller URLs are rejected by default; local development requires the explicit `C2HUNTER_ALLOW_INSECURE_CONTROLLER=true` override. Rotate or revoke a token when a Sensor is decommissioned or credentials may be exposed. mTLS gRPC is not implemented; ADR-0003 records the current contract.
3. Use managed or independently backed-up PostgreSQL/ClickHouse/Redis/object storage.
4. Put storage and Controller on private networks and expose only HTTPS.
5. Inject secrets from a secret manager, not `.env` or image layers.
6. Set retention, disk alerts, NTP, monitoring, RBAC, and restore drills.
7. Keep the human-readable image tag and immutable digest together in Compose, verify refreshed digests for every architecture in use, and scan them before promotion.

## 외부 Sensor 추가/제거

1. UI의 **External sensors → Enroll sensor**에서 Sensor와 복수 capture source를 만든다.
2. 각 interface에 방향과 BPF를 지정한다. 한 Agent에서 ingress와 egress interface를 각각 `INBOUND`/`OUTBOUND`로 설정할 수 있다.
3. `make sensor-agent`로 tarball을 만들고 외부 Linux에 복사한다.
4. tarball을 풀고 UI에서 한 번만 받은 token으로 설치한다.

```bash
sudo ./install-sensor.sh \
  --controller-url https://c2hunter.example.com \
  --enrollment-token '<ONE_TIME_TOKEN>'
sudo systemctl start c2hunter-sensor
journalctl -u c2hunter-sensor -f
```

Agent는 enrollment 후 credential과 desired config version을 `/var/lib/c2hunter-sensor/state/agent.json`에 mode `0600`으로 저장한다. 설정 변경은 중앙 UI에서 수행하며 Agent가 polling하거나 `systemctl reload c2hunter-sensor`할 때 안전하게 적용된다. 제거 시 먼저 capture/upload 완료를 확인하고 UI에서 credential을 revoke한 다음 서비스를 중지한다. Sensor identity와 token을 다른 장비에 재사용하지 않는다.

## Upgrade and rollback

Back up control metadata and object inventory, run tests and migrations in staging, pull/build pinned images, and roll Controller/Worker before sensors only when protocol compatibility allows. Keep the previous image digest and schema-compatible rollback procedure. Database migrations must be backed up and tested; never assume an application rollback reverses a migration.
