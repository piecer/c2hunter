# Accepted slice-1 execution addendum

Base: 1b262ff628a22aae8364152913747395225c0b44. This addendum supersedes conflicting draft clauses in 2026-10-25-network-improvement-followup.md. Parent adopts the independent review sections 3–7; no further user policy decision is pending.

Review binding: SHA-256 48ef7583e4558ff48eb15f0fc600bce754ea3ef46beece6a0ca2dee246878c2a. All file references below are repository-relative; C denotes the assigned candidate root, not permission to edit another worker's checkout.

Ownership refinement: one UI writer owns all shared Web product/context/selection paths and their Web tests. A separate native-fixture writer owns only the listed new Go test/PCAP and controller test, plus a new web/tests/network_native_capability_fixture.py adapter. No Go/controller/analysis production changes. The parent combines exact postimages before final cross-stack/native-browser acceptance. The UI writer must not claim the native witness passed before consuming its independently produced bytes.

Original source/report inputs remain immutable. Future backend planning continues against the untouched integration checkout while writers use separate detached candidates. No commit/push/deployment authority is added.

## 3. UI-4 확정 계약 — 작은 소비자 projection, raw 보존

`web/src/networkReportValidation.ts`(신규)의 순수 bounded projection을 현대 network view에서만 사용한다. API generic layer/producer/worker는 변경하지 않는다. 입력을 unknown으로 받고 원본을 mutate하지 않는다. 반환은 **overall summary 신뢰**, **각 issue의 유효성**, **각 example의 유효성**, **navigation ID의 유일성**을 독립적으로 표현한다. 하나의 recognized=false로 정상 sibling을 모두 버리는 현재 패턴을 유지하지 않는다.

### 구조/의미/상한

1. version=`network-pattern-report-v1`, nonarray object summary, array issues/warnings/limitations. issues length>100이면 length 검사에서 중단: 현대 issue registry를 만들거나 원소를 훑지 않고 명시적 '보고서 구조 한도 초과/Report structure limit exceeded'. legacy raw 객체는 그대로 둔다. unknown version은 unsupported이며 정상 legacy `network-anomaly-v1` 접근은 보존한다.
2. 10개 기존 summaryCounts는 nonnegative safe integer 필수. verdict는 3개 기존 enum, coverage_complete/truncated는 boolean 필수. `tracking_limited_records`, `counts_are_lower_bounds`, measurement_version/causes는 오래된 fixtures에 없으므로 **absence를 0/false로 합성하거나 무조건 invalid 처리하지 않는다**. 존재할 때 타입과 관계를 검사한다. title/flows 등 현대 view 미소비 additive 필드는 전체 schema exact-key 거부 사유가 아니다.
3. 필수 관계: evaluated/skipped/incomplete 각각 <= scanned; `scanned=skipped+incomplete+evaluated`; `displayed_issue_count=raw issues.length`; `issue_count=displayed+omitted`; `detailed_flow_count<=suspect_flow_count<=flow_count<=scanned`. 모든 연산 전에 safe integer 검사하고 overflow-safe 비교. available tracking_limited<=incomplete; tracking_limited>0이면 lower-bounds/truncated=true가 필요하다. **반대 명제는 금지**: upstream qualifiers는 limited=0에서도 lower-bounds/truncated=true이다. **truncated=true ⇒ coverage_complete=false도 금지**: producer issue truncation은 coverage_complete=true일 수 있다. issue/group event/host counts를 합쳐 summary flow/record와 같다고 요구하지 않는다.
4. clear는 위 summary 검사 + 알려진 warnings만/empty + coverage_complete=true + evaluated>0 + skipped/incomplete=0 + issue_count/displayed/omitted/issues 모두0 + truncated=false에서만 허용. valid positive partial/truncated는 observed + coverage warning이다. summary가 모순되면 overall은 '데이터 부족'과 항상 보이는 invalid/inconsistent 설명이며, 유효 positive issue는 **별도로 계속** 읽힌다. unknown warning/pattern/verdict는 unsupported semantics이지 추가 metadata key와 같지 않다.
5. issue core: id string 1..100, 6개 pattern enum, severity=`observation`, scope object(sensor_id 1..256, interface null 또는 uint32, protocol TCP/UDP/ICMP/ICMPV6, peer endpoint), nonnegative safe event/flow/host/omitted counts, first_seen/last_seen bounded string<=64, examples array<=10. endpoint는 object/ip string 1..45, port null 또는 integer 0..65535. 여기서는 새 timestamp 정렬·위험도·IP heuristic을 발명하지 않는다. JSON primitive/null/array 잘못된 타입은 local invalid로 표시한다. evidence/uncertainty/next_checks는 list이어야 하며 표시 prefix에서 string만 사용; 없는 필드는 '미제공'으로 표시해 healthy 근거로 사용하지 않는다. id 실패는 navigation 불가이고 나머지 독립 증거까지 무조건 제거하지 않는다.
6. examples=[null], endpoint null, facts scalar/array는 그 **example/field**에 invalid 설명. 유효한 같은 issue 예시와 다른 issue를 계속 보여준다. examples>10이면 그 예시 collection을 거부하되 issue core의 관찰은 보존. facts absent는 기존 fixture와 호환되는 미제공, facts object는 6개 기존 numeric fact keys를 직접 lookup하여 타입/producer maxima 검사한다(`network_ai.py:297–304`). unknown additive keys는 읽거나 펼치지 않고 원본 보존. 0은 정상, missing은 unknown. measurements는 기존 NetworkMeasurements/quality 경로 유지; optional 신규 subtree failure를 sibling 제거 조건으로 쓰지 않는다.
7. 배열 순회 상한: issue100/example10, warnings2048, 표시 notes 기존 prefix(4/limitations8), AI 섹션 prefix20/각 ID prefix20/문자2000. warnings>2048은 원소 순회 전 overlimit feedback; <=2048은 known warning 모두 dedupe 노출(기존 1000-unknown 회귀 보존). unknown field 전체 Object.entries/JSON.stringify를 검증 목적으로 순회하지 않는다. raw entire AI result의 기존 JSON.stringify owner key도 navigation provenance로 재사용하지 않는다. 문자열 길이 검사는 O(1), 표시만 bounded slice.

**fixture 정리:** 기존 수동 테스트의 25 tracking-limited/0 incomplete 같은 실제 불가능한 수치 조합(`NetworkReport.test.tsx:68–75`)을 producer-generated limited positive로 대체한다. 원래 assertion인 positive 보존·경고 노출은 유지한다. missing optional fields control은 제거하지 않는다.

## 4. UI-2 확정 계약 — current run + immutable job + 현재 화면 세대

### 현재 API로 가능한 것 / 불가능한 것

Run에 실제 필드 `analysis_job_id`, `dataset_id`, `network_input`를 optional로 읽는 타입을 추가한다. **prompt_hash는 입력 보고서 hash가 아니다.** public network_input은 bounded projection이며 scope/endpoints와 모든 optional raw evidence를 포함하지 않으므로 이것만으로 arbitrary 저장 변조 전후 전체 report byte identity를 증명할 수 없다.

이번 slice는 지원 API의 **완료 job report 불변성**을 source authority로 사용한다. 인용 actionable 조건은 다음을 모두 만족해야 한다.

- 실제 App job.id와 current displayed run.analysis_job_id가 정확히 같고 NETWORK_ANOMALY/COMPLETED 및 지원 interpretation/input schema이다.
- dataset 양쪽 값이 있으면 동일해야 한다. dataset만으로 허용하지 않는다. analysis_job_id 누락/불일치, run detail.id가 선택한 latest.id와 다른 경우는 non-actionable.
- network_input.issues는 <=20의 유효 unique ID이며 대상 ID를 포함한다. 해당 projection item의 pattern/counts/first_seen/last_seen이 현재 유효 issue의 같은 필드와 일치한다. 입력에 포함되지 않은 report ID는 '이 AI 실행의 입력 근거에 없음'. 100개 보고서의 21..100번째 ID가 여기에 해당한다.
- report registry는 <=100 raw 슬롯에서 ID를 Map으로 세어 **invalid sibling에 있더라도 duplicate ID는 ambiguous**로 막는다. 같은 pattern/peer/sensor를 검색하거나 CSS selector에 ID를 삽입하지 않는다. duplicate citation 자체는 항목 내부에서 dedupe하여 control 증식 금지; 다른 원인/다음확인 항목에서의 정상 재인용은 허용한다.
- stale handler는 capture한 job identity, report generation, displayed run identity가 현재 모두 같을 때만 동작한다. report object 교체 때 generation은 새로 발급하며 이전 callback은 같은 A object가 다시 와도 실패한다. metadata-only refetch로 동일 report data가 재구성될 때도 callback 세대는 갱신하되 새 control은 다시 검증할 수 있다.
- 같은 job에서 이미 바인딩했던 report의 **소비하는 evidence 내용이 변경된 것을 관찰**하면 그 run의 인용은 신뢰 불가로 latch하여 A→B→A에서도 부활시키지 않는다. bounded validated projection 비교만 사용. 완전히 새로운 run을 현재 report와 새로 바인딩하면 사용 가능하다. 앱 route 재마운트의 baseline은 지원 API의 immutable job 계약이다. 이는 저장 변조 탐지/암호학적 보장이 아님을 명시한다.

위 불변성 가정 없이 'saved report 어느 바이트 버전인가'까지 보장해야 한다면 실제 producer에서 산출·저장·공개하는 공통 `source_report_digest` 또는 report revision token이 job+run 모두에 추가로 필요하다. **이번 slice에서 그 새 backend 계약을 만들지 않는다.** 출처 부족/불일치는 텍스트 인용+한/영 '현재 보고서와 출처를 확인할 수 없어 이동할 수 없습니다'로 보수화한다. 기존 provenance 없는 saved-run fixture는 가설/인용 텍스트 표시를 유지하되 링크를 억지로 살리지 않는다.

### 이동 동작

현재 ReportDetailContext의 evidence 소유권을 claim하고 AI full subtree를 unmount한다. 실제 report page를 `floor(rawIndex/8)`로 선택하고 전체 그룹 목록을 연 뒤 해당 issue detail 한 개를 연다. section ref로 focus/scroll; heading 또는 evidence region tabIndex=-1. `<button type=button>`으로 Enter/Space 활성화. 해당 article에는 literal issue ID를 표시한다. aria-controls는 현재 mount된 대상에만 둔다. 정적 ID 문자열을 URL/HTML/CSS selector로 해석하지 않는다. 페이지는 valid sibling filtering 전에 원래 raw ordinal을 기준으로 유지하여 malformed sibling 때문에 다른 evidence로 오프셋 이동하지 않는다. invalid 슬롯은 짧은 placeholder로 나타내거나 동일 raw range 안에서 생략 수를 명시한다.

## 5. M2 closed capability table (표현만; admission/검출 변경 없음)

`App.tsx:589–619`의 현재 uncontrolled mode select는 초기 LIVE를 유지하는 controlled state로 바꿔 설명을 즉시 갱신하되 name=mode/FormData 값과 제출 body는 그대로다. PCAP upload callsite는 명시적 upload context를 전달한다. source disclosure를 결과 panel에 전달하며 기존 Job details를 펼치지 않아도 보인다. ko/en 사용. generic NetworkObservationHelp의 ICMP echo RTT 등 현재 modern producer가 제공하지 않는 무조건적 기능 약속은 제거한다.

| 입력/실제 metadata | 고정 분류 | 안내하는 가능 범위 | 반드시 안내할 한계 |
|---|---|---|---|
| 새 선택 LIVE | native LIVE aggregate | 센서 흐름·패킷/바이트 집계 수집 | 현재 native 경로는 network packet-evidence를 전달하지 않음; 패킷별 TCP/UDP/ICMP 패턴·exact RTT/spacing/TTL 시계열을 이 집계에서 복원하지 않음 |
| 새 선택 HISTORICAL | historical sensor aggregates | 보존된 sensor flow snapshot 재사용 | 과거 선택/시간 범위 변경이 packet evidence를 생성하지 않음 |
| upload 선택 | packet-level PCAP input path | 지원 packet records의 6패턴과 packet 기반 supporting measurements를 분석 가능 | 양방향·타임스탬프·필드/프로토콜·표본·파서/캡 제한 조건부; 모든 metric 보장 아님 |
| source_type=SENSOR_CAPTURE, mode=LIVE | sensor LIVE origin | 위 native 경로 설명 | report에 실제 positive가 있으면 보존; 이 metadata가 개별 레코드 모두 aggregate임을 증명하지는 않음 |
| SENSOR_CAPTURE, HISTORICAL | historical sensor origin | 보존 sensor records | historical이라는 이유로 packet capability로 승격 금지 |
| SENSOR_CAPTURE, REANALYSIS | sensor-origin reanalysis | 같은 sensor dataset 재분석 | 원래 LIVE/HISTORICAL 구분은 현재 응답만으로 알 수 없음; 추측/parent fetch 없음 |
| PCAP_UPLOAD, PCAP_UPLOAD | uploaded PCAP origin | packet path 설명 | complete coverage 또는 특정 측정 보장 아님 |
| PCAP_UPLOAD, REANALYSIS | uploaded-PCAP-origin reanalysis | 유지된 PCAP source 설명 | 재분석은 새 job; 새 캡처 또는 현재 sensor packet 확장 아님 |
| source_type/mode 누락·unknown·위 표에 없는 충돌 조합 | unknown/conflicting provenance | 검증된 report observation만 따로 표시 | source capability 확인 불가; mode/packet_count==1/timing/source filename만으로 추정 금지 |

근거: `jobs.py:174–195`는 source_type을 생성하고, `app.py:4714,4729–4748`는 재분석에서 mode=REANALYSIS와 source_type/source/coverage를 보존한다. 부모 작업을 fetch해서 가계도를 재구성할 필요 없다. `test_network_report_live.py`는 PCAP dictionary를 LIVE ingestion에 넣는 정상 transport test이지 native producer 지원 proof가 아니다. 그 positive control은 계속 유지하고 capability 문구가 결과를 가리지 않게 한다.

항상 수동·수동적 다음 행동: **사용 가능한 적절한 양방향 packet-level PCAP를 별도 분석**. store_pcap 체크/업로드 여부가 현재 aggregate report를 소급 보강한다고 쓰지 않는다. LIVE 시작 버튼 비활성화/422 추가/프로토콜 전송 확장은 금지. C2/DDoS submit, 동의, idempotency, reanalysis semantics는 변경하지 않는다.

## 6. 정확한 단일 writer 소유 경로

모두 C-relative. 기존 App+panel+report+AI를 **한 writer**가 소유한다. 병렬 backend detector writer에게 넘기지 않는다.

**제품(기존):**
- `web/src/App.tsx`
- `web/src/NetworkAnomalyPanel.tsx`
- `web/src/NetworkPatternReport.tsx`
- `web/src/NetworkAIInterpretation.tsx`
- `web/src/reportDetailContext.ts`

**제품(신규, 현재 없음 확인):**
- `web/src/networkReportValidation.ts` — bounded DTO/registry pure helper
- `web/src/networkEvidenceContext.ts` — job/report generation과 navigation 인터페이스만; 기존 detail owner를 대체하지 않음
- `web/src/NetworkSourceCapability.tsx` — 위 closed classification와 ko/en 표기

**테스트/fixture(신규):**
- `web/tests/NetworkReportValidation.test.tsx`
- `web/tests/NetworkCitationNavigation.test.tsx`
- `web/tests/NetworkSourceCapability.test.tsx`
- `web/e2e/network-citation-capability.spec.ts`
- `controller/tests/test_network_native_capability.py`
- `sensor/internal/flowbatch/network_capability_test.go` (package flowbatch_test; offline decoder→aggregator→flowbatch witness)
- `sensor/internal/flowbatch/testdata/network_capability_six.pcap` (owned synthetic six packets; 생성 출처 기록)

**필요한 기존 test 교정/확장 소유:**
- `web/tests/NetworkReport.test.tsx` (oversize/불가능 수치 fixture 분리)
- `web/tests/NetworkGlance.test.tsx` (report-only budget 보존; 새 AI bound 분리)
- `web/tests/NetworkAIAudit.test.tsx` (문자 인용을 control로 바꿀 때 container text exact-match만 호환 교정; markup 금지/20 prefix 유지)
- `web/tests/NetworkReportPagination.test.tsx`
- `web/tests/App.test.tsx`
- `web/tests/network_report_fixture.py` (100/10 producer generator 및 정확한 input bundle/run fixture 생성)

나머지 NetworkAIRunReconciliation/NetworkAI/NetworkSourceCoverage/NetworkWarningCompleteness/NetworkMeasurements tests는 우선 unchanged regressions. 불가피한 fixture 교정은 소유권을 부모에게 먼저 명시하며 행동 assertion을 약화하지 않는다. backend production 0개, Go production 0개, api.ts/schema producer 변경 0개. 문서/plan은 부모 단독 소유이며 App나 report에 두 writer를 dispatch하지 않는다.

## 7. 실행 가능한 RED / 정상대조 / GREEN acceptance matrix

각 RED는 **목표 행동을 assertion하여 기준 source에서 실패**시킨 뒤 제품을 수정한다. 아래 일부 fault는 이번 characterization에서 현재 실패 현상을 확인했지만 목표 assertion test 작성/실행을 대체하지 않는다.

| ID / 테스트 파일 | RED 입력·관찰 | 반드시 통과할 정상대조 및 GREEN |
|---|---|---|
| V1 / NetworkReportValidation | 실제 normal에 scanned0/evaluated999/displayed7/issues[]; invalid summary/unsafe int/boolean-as-count/null summary | invalid feedback visible, clear 없음, throw 없음, raw deepFreeze 불변; 원래 normal clear 유지 |
| V2 / 동일 | positive의 examples=[null, valid], endpoint null, facts scalar/array, scope malformed, missing consumed fields | invalid 부분 설명, 유효 sibling/예시/positive 유지; localized error·coverage 존재, raw unchanged |
| V3 / 동일 | unknown pattern/warning/verdict, unknown version, additive key 각각 독립 | unsupported semantics는 trusted overall 불가; valid sibling 유지; additive metadata는 정상 표시와 observation 동일; legacy toggle 유지 |
| V4 / 동일+fixture | 101 issue/11 example, huge warning list | preflight 한도 거부와 제한된 error DOM; 100/10 실제 producer와 1000 unknown+known warning 기존 control 통과 |
| V5 / 동일+producer | complete/partial/limited/upstream/truncated | 실제 수치 관계 보존. upstream limited0/lowerbounds true, truncation coverage_complete true도 valid. 불완전 positive를 healthy/전체거부로 바꾸지 않음 |
| C1 / NetworkCitationNavigation | 정상 20-retained report와 current run의 마지막 ID를 causes/checks/correlations 각각 클릭 | Enter/Space→실제 Page3/3→정확한 literal ID detail focus+visible. 같은 pattern/peer, 다른 sensor/interface에서도 exact ID만 선택 |
| C2 / 동일 | missing/unknown/omitted ID, duplicate raw issue ID(한쪽 malformed 포함), wrong job, wrong dataset, missing source fields, wrong input facts, report100의 ID100을 output에 fault주입 | non-actionable+이유; valid current run의 first20 대상은 정상. duplicate refs는 항목내 control1개. URL/extra GET/POST/cancel 없음 |
| C3 / 동일 | report replacement 같은 ID/count 다른 evidence; source A→B→A; 같은 report object 두 cached job; 지연 old run detail/old callback | 이전 handler 무효, page/detail 초기화, old-run changed-report 인용 latch, 새 verified run만 이동. 목록 reconciliation/consent/manual-only 기존 tests 그대로 |
| C4 / 동일+Glance | actual producer100×10, native-valid output10×20×3 + 12 limitations; legacy display20×20×3 prefix | 실제 document.querySelectorAll('*') 초기/AI full/인용후/페이지/각 detail/닫힘 최대<=2500, hidden 포함. single owner. 기존 report-only<500 유지. current model first20와 report100 pagination을 혼동하지 않음 |
| M1 / NetworkSourceCapability+App | 새 network LIVE↔HISTORICAL 변경, upload 선택 | submit 전 문구 변경; FormData mode, 시작 허용, capture flags 동일. C2 및 DDoS 선택/submit bodies·idempotency 그대로 |
| M2 / 동일 | §5 모든 metadata row, PCAP reanalysis, sensor reanalysis, missing/unknown/conflict | 한/영 고정문구, details 닫혀도 visible; 알려진 positive를 source label로 숨기지 않음; unknown을 LIVE로 fallback하지 않음 |
| M3 / native Go+controller+Web | 같은 6 synthetic packet bytes를 native offline decoder→aggregator→batch→FlowRecord→실제 worker→public job→Web | native batch packet total6, directional rows2, packet_evidence_complete false, evaluated0/incomplete2/insufficient+명확한 aggregate capability. 같은 bytes의 PCAP parser→worker control은 evaluated6 및 실제 positive 유지 |
| B1 / owned Playwright | actual built App+fixture API, ko/en, 1280/390px, cached A/B/A | genuine keyboard activation/focus/visible target, no overflow/console errors, DOM<=2500, no inference request. 이것은 localhost fixture acceptance이고 LIVE/실모델/스크린리더 수용성 proof 아님 |

M3의 native witness는 이전 audit `probes/measurements/native_main.go`의 실제 APIs(capture.NewOfflineReader, flow.NewAggregator, flowbatch.New)를 그대로 현재 revision에서 사용하는 시험으로 만든다. read-only module imports 때문에 internal Go runner를 외부 임의 디렉터리에서 곧바로 go run하지 말 것: 새 package flowbatch_test의 전용 test 또는 allowlisted sensor source를 owned tmp module로 복사한 runner를 사용한다. test output은 invocation-owned path로 전달한다. `test_network_report_live.py`를 이 witness 대신 재명명하지 않는다. 6 packet의 source bytes와 packet control 동일 SHA를 기록한다.

### writer의 좁은 명령 계약

- 작업 cwd C/web, Node `/home/piecer/.nvm/versions/node/v22.22.3/bin/node`, private installed `node_modules/vitest/vitest.mjs`를 직접 실행. `vitest run tests/NetworkReportValidation.test.tsx tests/NetworkCitationNavigation.test.tsx tests/NetworkSourceCapability.test.tsx`로 RED→GREEN. private config에서 envDir/cacheDir를 owned tmp로 지정하고 setupFiles는 C/web/tests/setup.ts, root는 C/web. 실제 C .env 자동 load 금지.
- 같은 설정으로 기존 Network*.test.tsx + App.test.tsx 회귀. fixture interpreter는 절대 C/.venv/bin/python; PYTHONPATH는 C/controller/src:C/analysis/src:C/sensor/worker/src:C/analysis/tests; PYTHONDONTWRITEBYTECODE=1.
- native focused: C/sensor에서 `go test ./internal/flowbatch -run '^TestNetworkAggregateCapabilityFixture$' -count=1` (정확히 이 test 이름으로 작성), GOPROXY=off/GOSUMDB=off/GOTOOLCHAIN=local 및 owned GOCACHE/GOTMPDIR. 부족 dependency는 설치/네트워크 fallback하지 말고 blocker.
- controller focused: C/.venv/bin/python `-m pytest -q controller/tests/test_network_native_capability.py -p no:cacheprovider` 및 owned basetemp. 실제 imports와 fixture 경로 assertion.
- browser는 설치된 Playwright/Chromium만 사용, private build/preview/fixture server와 private envDir, 고정 허용 loopback. production9001 아님.
- 이 후 부모의 canonical `make test`, `make lint` 및 허용 source builds는 별도 gate. Makefile build가 docker compose --env-file .env까지 수행하므로 **make build 전체는 권한밖**이다. compileall/source Go/Web build만 한정해야 한다. 현재 검토에는 이 expensive gate들을 실행할 권한/필요가 없었다.
