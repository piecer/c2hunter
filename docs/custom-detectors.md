# Custom Detector Framework

C2Hunter는 운영자가 설치한 Python detector를 built-in detector 뒤에 결정적인 파일명 순서로 실행한다. Controller의 in-process 분석과 worker 분석은 동일한 registry 규칙을 사용한다.

## 보안 경계

Custom detector는 sandbox가 아니다. Plugin import와 `analyze()`는 C2Hunter 프로세스 안에서 실행되므로 해당 프로세스 권한으로 코드와 파일에 접근할 수 있다.

- 신뢰할 수 있는 운영자만 plugin 디렉터리에 파일을 배포한다.
- 분석 API payload로 plugin 경로를 받지 않는다.
- `C2HUNTER_CUSTOM_DETECTORS_DIR` 환경변수로 지정한 로컬 디렉터리만 읽는다.
- `.py` regular file만 로드한다. 숨김 파일, `_`로 시작하는 파일, 경로 구성요소의 symlink와 허용 디렉터리 밖 경로는 로드하지 않는다.
- 정규화된 디렉터리 경로별 registry는 eviction 없이 프로세스 수명 동안 cache된다. 추가·수정·삭제 후 Controller와 worker를 재시작한다.
- 신뢰할 수 없는 detector를 실행해야 한다면 별도 process/container 격리가 필요하다.

## Plugin 계약

각 script는 다음 중 하나를 export해야 한다. 위에서부터 우선한다.

1. `DETECTOR`: `name`, `version`, 동기 `analyze(context)`를 제공하는 객체
2. `create_detector()`: 위 객체를 반환하는 zero-argument factory
3. `analyze(context)`: module-level 동기 함수

함수형 plugin은 `DETECTOR_NAME`과 `DETECTOR_VERSION`을 선택적으로 선언할 수 있다. 생략하면 파일 stem과 `1.0.0`을 사용한다.

```python
# /opt/c2hunter/custom-detectors/example_rule.py
from c2hunter_analysis.domain import AnalysisContext, Evidence

DETECTOR_NAME = "example_rule"
DETECTOR_VERSION = "1.0.0"


def analyze(context: AnalysisContext) -> list[Evidence]:
    # 실제 rule은 context.flows와 context.parameters를 검사한다.
    if not context.flows:
        return []
    return [
        Evidence(
            candidate_ip=context.flows[0].destination_ip,
            type="COMMON_DESTINATION",
            detector="placeholder",  # Framework가 실제 plugin 이름으로 정규화한다.
            version="placeholder",  # Framework가 실제 plugin 버전으로 정규화한다.
            raw_score=5,
            contribution=5,
            description="Example custom rule matched",
        )
    ]
```

## 실행과 검증 규칙

- `analyze`는 정확히 하나의 `AnalysisContext`를 받고 `list[Evidence]`를 반환하는 동기 callable이어야 한다.
- Plugin 예외는 `DetectorExecutionError`로 wrapping되며 분석을 실패시킨다. 잘못된 detector를 조용히 건너뛰지 않는다.
- 반환값은 실제 `Evidence` instance만 허용한다.
- `candidate_ip`는 유효한 IPv4 또는 IPv6 주소여야 한다.
- `raw_score`와 `contribution`은 bool이 아닌 finite number이며 0–100 범위여야 한다. `confidence`는 0–1 범위다.
- `first_seen`과 `last_seen`은 값이 있으면 timezone-aware `datetime`이어야 하며 `first_seen <= last_seen`이어야 한다.
- `metrics`는 string key와 표준 JSON 값만 허용한다. 정수는 JavaScript safe integer 범위이며 순환 참조, `datetime`, NaN과 infinity는 거부한다.
- Scoring 예약 metric인 `sample_count`는 0 이상의 safe integer, `public_dns_ntp`와 `cdn_cloud`는 boolean, `match_mode`는 string이어야 한다.
- 분석 한 번에 plugin 하나가 반환할 수 있는 Evidence는 최대 10,000개다.
- 현재 scoring cap이 정의된 evidence type만 허용한다. 알 수 없는 type을 0점으로 조용히 저장하지 않는다.
- Custom detector 이름은 다른 custom detector 및 built-in detector 이름과 중복될 수 없다.
- Custom Evidence의 `detector`와 `version`은 등록된 plugin metadata로 정규화되어 결과 provenance를 보존한다.
- 현재 custom detector weight는 기본값 `1.0`이다. Controller의 분석 설정 schema에 등록되지 않은 custom weight는 허용하지 않는다.

## 배포

운영 배포에서는 Controller와 worker 모두에 같은 detector directory를 read-only로 mount하고 같은 환경변수를 설정한다.

이미지는 비특권 UID `65532`로 실행된다. Host directory에는 traverse 권한이, plugin 파일에는 read 권한이 있어야 한다. 권장 권한은 directory `0755`, Python 파일 `0644`이며 쓰기 권한은 mount의 `:ro`로 차단한다.

```yaml
# 운영 compose override 예시: 기본 docker-compose.yml에는 임의 코드를 mount하지 않는다.
services:
  controller:
    environment:
      C2HUNTER_CUSTOM_DETECTORS_DIR: /opt/c2hunter/custom-detectors
    volumes:
      - ./custom-detectors:/opt/c2hunter/custom-detectors:ro
  worker:
    environment:
      C2HUNTER_CUSTOM_DETECTORS_DIR: /opt/c2hunter/custom-detectors
    volumes:
      - ./custom-detectors:/opt/c2hunter/custom-detectors:ro
```

한쪽에만 plugin을 설치하면 같은 job이 실행 위치에 따라 다른 결과를 낼 수 있으므로 Controller와 worker의 디렉터리 내용과 plugin version을 함께 관리한다.
