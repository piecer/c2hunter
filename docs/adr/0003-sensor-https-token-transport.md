# ADR-0003: Sensor HTTPS/token 전송을 현재 운영 계약으로 채택

- 상태: 승인
- 날짜: 2026-08-14
- 대체 대상: ADR-0001의 결정 2, SPEC.md §4.2/§5.1의 전송 구현 가정

## 컨텍스트

ADR-0001과 초기 SPEC는 Sensor→Controller outbound mTLS gRPC stream을 MVP 계약으로 정했다. 현재 구현은 이 계약과 다르다. Go Sensor는 HTTP/HTTPS Controller URL만 허용하며 등록, heartbeat, configuration polling, flow batch, PCAP segment 전송을 `/api/v1` endpoint로 수행한다. Enrollment claim으로 발급받은 agent token을 이후 요청의 `X-Sensor-Token` header로 사용한다. `grpc://` URL은 명시적으로 거부한다.

문서만 gRPC라고 유지하면 운영자가 존재하지 않는 gateway와 인증서 수명주기를 전제로 배포하게 된다. 반대로 이번 변경에서 검증되지 않은 gRPC gateway를 급히 추가하는 것은 transport, retry, ACK, identity, 배포 경계를 동시에 바꾸므로 안전하지 않다.

## 결정

1. 현재 지원 전송은 Sensor가 시작하는 outbound HTTP/HTTPS 요청과 polling이다.
2. 운영 배포 계약은 Sensor→Controller 구간 전체의 HTTPS다. Sensor 설정은 원격 `http://` URL을 기본 거부하며 local development에서만 `C2HUNTER_ALLOW_INSECURE_CONTROLLER=true`를 명시적으로 설정할 수 있다.
3. Sensor identity는 일회성 enrollment claim 이후 발급되는 agent token을 `X-Sensor-Token` header로 검증한다. token은 로그 출력을 금지하고 회전/폐기를 지원한다. Sensor state file의 평문 credential 보호는 OS file permission과 host 보안 경계에 의존한다.
4. `proto/sensor.proto`는 향후 streaming transport의 설계 초안으로 보존하되 현재 구현 계약이나 생성 코드의 권위로 취급하지 않는다.
5. mTLS gRPC를 다시 도입하려면 별도 ADR, gateway 구현, protobuf compatibility test, certificate issuance/rotation/revocation, reconnect/backpressure/ACK integration test와 HTTP migration 계획이 모두 필요하다.

## 결과

- 문서와 실행 코드의 전송 방식이 일치한다.
- NAT/방화벽 내부 Sensor가 Controller로 outbound 연결한다는 원래 네트워크 요구는 유지된다.
- HTTPS 종료 지점과 Controller 사이가 평문이면 보호되지 않으므로 production reverse proxy는 private network에 두고 해당 hop도 TLS로 보호해야 한다.
- token은 certificate-bound identity가 아니므로 유출 시 폐기·회전이 필요하다.

## 검증

- `sensor/internal/transport/http_test.go`는 HTTP/HTTPS endpoint 계약과 `grpc://` 거부를 검증한다.
- Controller sensor enrollment/API 계약 테스트는 claim, agent token, rotate/revoke 경계를 검증한다.
