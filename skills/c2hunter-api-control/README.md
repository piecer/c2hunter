# C2Hunter 외부 AI 제어 SKILL

시작 파일은 `SKILL.md`다. 다른 AI 에이전트에 이 폴더 전체를 전달하고 SKILL.md를 읽도록 지시한다. Python/터미널 실행 도구가 없는 AI에는 별도의 tool/function/MCP 연결이 필요하다. 이 번들 자체가 MCP 서버는 아니다.

## 구성

- `SKILL.md`: AI가 따를 절차·권한·실패 처리 원칙
- `references/workflows.md`: 한국어 작업 순서와 명령 예제
- `references/operations.json`: 허용 작업·경로·권한·인수 계약
- `references/openapi.json`: C2Hunter 소스에서 생성한 API 스키마
- `scripts/client.py`: Python 표준 라이브러리만 사용하는 호출 도구
- `examples/`: PCAP 작업 생성·AI 요청·취소 JSON 예제
- `tests/`: 클라이언트 및 실제 애플리케이션 계약 검증

## 첫 실행

인증이나 네트워크 없이 작업 목록을 확인할 수 있다:

    python scripts/client.py describe

실제 호출은 운영자가 `C2HUNTER_BASE_URL`과 `C2HUNTER_API_TOKEN`을 안전하게 프로세스 환경에 설정한 뒤 수행한다. 토큰은 이 문서·채팅·명령행에 입력하지 않는다.

    python scripts/client.py request openapi-get
    python scripts/client.py request jobs-list --query page=1 --query page_size=20

외부 AI에 줄 지시 예:

> 이 폴더의 SKILL.md와 references/workflows.md를 읽고, 운영자가 승인한 C2Hunter에 대해 먼저 읽기 전용으로 상태와 분석 작업을 확인하세요. 인증 토큰을 출력하지 마세요. 분석 생성·업로드·AI 실행·취소는 해당 작업을 명시적으로 승인받은 경우에만 하세요. 실패한 쓰기를 자동 재시도하지 마세요.

`--allow-write`는 이미 받은 작업 승인을 명시하는 플래그이지 자동 승인 수단이 아니다. 제공된 JSON 예제의 내부망·파일명·멱등 키를 그대로 실제 작업에 재사용하지 않는다.

API 설명의 원본은 저장소의 `docs/external-api-reference.md`, `docs/ai-c2-analysis-api.md`이며, 배포 버전은 인증된 `/openapi.json` 조회로 확인한다. 생성된 스냅샷과 현재 운영 버전이 같다고 가정하지 않는다. 운영 서버의 모델 실행·LIVE 캡처·배포는 이 스킬의 오프라인 검증과 별개다.
