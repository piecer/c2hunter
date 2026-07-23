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

1. Terminate HTTPS at a maintained reverse proxy; disable development login. For offline analysis, configure that proxy to accept at least 500 MiB request bodies and allow at least 10 minutes for upload processing.
2. Require Controller↔Sensor mTLS and validate identity, EKU, expiry, and revocation.
3. Use managed or independently backed-up PostgreSQL/ClickHouse/Redis/object storage.
4. Put storage and Controller on private networks and expose only HTTPS.
5. Inject secrets from a secret manager, not `.env` or image layers.
6. Set retention, disk alerts, NTP, monitoring, RBAC, and restore drills.
7. Pin images by digest in the release manifest and scan them before promotion.

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
