export type Axis = { confidence: string; supporting_codes: string[]; counter_codes: string[]; unknown_codes: string[] };
export type AxisEvidence = Record<string, number | boolean | null>;
export const axisNames = ['delivery_mechanism', 'source_population', 'source_authenticity'] as const;
const counters = ['observed_sources', 'sample_count', 'omitted_samples', 'unobserved_packets', 'eligible_sources', 'coordinated_sources', 'shared_buckets', 'response_samples', 'request_samples', 'matched_response_samples', 'direct_samples', 'invalid_source_records', 'identity_variation_records', 'component_count'];
const closed = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => {
  if (typeof v !== 'object' || v === null || Array.isArray(v) || Object.getPrototypeOf(v) !== Object.prototype) return false;
  const own = Reflect.ownKeys(v);
  return own.length === keys.length && own.every(k => typeof k === 'string' && keys.includes(k)
    && Object.getOwnPropertyDescriptor(v, k)?.enumerable && Object.hasOwn(Object.getOwnPropertyDescriptor(v, k)!, 'value'));
};
const sameCodes = (v: unknown, expected: string[]) => Array.isArray(v) && v.length === expected.length
  && Reflect.ownKeys(v).length === v.length + 1
  && expected.every((s, i) => Object.getOwnPropertyDescriptor(v, String(i))?.value === s);

export function validV3Classification(value: unknown): boolean {
  if (!closed(value, [...axisNames, 'confidence', 'evidence', 'axes'])) return false;
  if (!closed(value.evidence, [...counters, 'coverage_limited', 'window_seconds', 'amplification_ratio'])) return false;
  const raw = value.evidence;
  if (!counters.every(k => typeof raw[k] === 'number' && Number.isSafeInteger(raw[k]) && Number(raw[k]) >= 0)
    || typeof raw.coverage_limited !== 'boolean' || raw.window_seconds !== 10 || raw.amplification_ratio !== null) return false;
  const e = raw as Record<string, number>;
  if (e.matched_response_samples > e.response_samples
    || e.response_samples + e.request_samples + e.direct_samples > e.sample_count
    || e.coordinated_sources > e.eligible_sources || e.eligible_sources > e.observed_sources
    || e.shared_buckets > 10 || e.sample_count > 32768 || e.eligible_sources * 3 > e.sample_count
    || (!e.component_count && e.sample_count > 2048)
    || e.coordinated_sources * e.shared_buckets > e.sample_count - e.response_samples) return false;
  const limited = raw.coverage_limited || e.omitted_samples > 0 || e.unobserved_packets > 0;
  const reflection = e.response_samples > e.matched_response_samples;
  const direct = e.direct_samples + e.request_samples > 0;
  const coordinated = e.coordinated_sources >= 3 && e.shared_buckets >= 3 && !limited;
  const delivery = reflection && direct ? 'MIXED' : reflection ? 'REFLECTION_AMPLIFICATION' : direct ? 'DIRECT_DISTRIBUTED' : 'UNKNOWN';
  const population = e.component_count ? 'MIXED' : coordinated ? 'BOTNET_LIKE_COORDINATION' : reflection && !direct ? 'REFLECTOR_SET' : 'DISTRIBUTED_UNATTRIBUTED';
  const authenticity = e.invalid_source_records ? 'SPOOFING_SUSPECTED' : 'SPOOFING_UNCONFIRMED';
  const axes: Record<string, Axis> = {
    delivery_mechanism: {
      confidence: reflection && !limited ? 'medium' : 'low',
      supporting_codes: reflection ? ['PARSED_RESPONSE_OBSERVED'] : direct ? ['DIRECT_PACKET_PROFILE_OBSERVED'] : [],
      counter_codes: e.matched_response_samples ? ['MATCHING_REQUEST_OBSERVED'] : [],
      unknown_codes: e.response_samples ? ['AMPLIFICATION_UNMEASURED', 'REQUEST_VISIBILITY_NOT_PROOF', 'UPSTREAM_SPOOFING_UNCONFIRMED'] : !direct ? ['RESPONSE_SEMANTICS_UNAVAILABLE'] : [],
    },
    source_population: {
      confidence: coordinated && !e.component_count ? 'medium' : 'low',
      supporting_codes: coordinated && !e.component_count ? ['SHARED_PROFILE_AND_PACKET_TIMING'] : [],
      counter_codes: e.eligible_sources >= 3 && !coordinated ? ['NO_SHARED_TEMPORAL_PROFILE'] : [],
      unknown_codes: e.component_count ? ['COMPONENT_ASSESSMENTS'] : coordinated ? ['LEGITIMATE_COORDINATION_POSSIBLE', 'COMPROMISE_UNCONFIRMED'] : ['PACKET_TIMING_OR_PROFILE_UNAVAILABLE'],
    },
    source_authenticity: {
      confidence: e.invalid_source_records && !limited ? 'medium' : 'low',
      supporting_codes: e.invalid_source_records ? ['INVALID_SOURCE_ADDRESS_OBSERVED'] : [],
      counter_codes: [],
      unknown_codes: ['SOURCE_VALIDATION_UNAVAILABLE', ...(e.identity_variation_records ? ['TTL_IPID_VARIATION_NOT_PROOF'] : [])],
    },
  };
  if (limited) Object.values(axes).forEach(a => a.unknown_codes.push('EVIDENCE_COVERAGE_LIMITED'));
  if (value.delivery_mechanism !== delivery || value.source_population !== population || value.source_authenticity !== authenticity
    || value.confidence !== (limited ? 'low' : coordinated || reflection || e.invalid_source_records ? 'medium' : 'low')
    || !closed(value.axes, axisNames)) return false;
  return axisNames.every(name => {
    const actual = (value.axes as Record<string, unknown>)[name], expected = axes[name];
    return closed(actual, ['confidence', 'supporting_codes', 'counter_codes', 'unknown_codes'])
      && actual.confidence === expected.confidence
      && sameCodes(actual.supporting_codes, expected.supporting_codes)
      && sameCodes(actual.counter_codes, expected.counter_codes)
      && sameCodes(actual.unknown_codes, expected.unknown_codes);
  });
}

export const axisReasons: Record<string, [string, string]> = {
  PARSED_RESPONSE_OBSERVED: ['Parsed response headers observed; reflection remains a suspicion.', '응답 헤더 관찰: 반사는 의심 단계입니다.'],
  DIRECT_PACKET_PROFILE_OBSERVED: ['Direct packet profiles observed.', '직접 패킷 프로파일 관찰.'],
  MATCHING_REQUEST_OBSERVED: ['Matching requests are counterevidence to unsolicited reflection.', '일치하는 요청은 비요청 반사 추정의 반증입니다.'],
  AMPLIFICATION_UNMEASURED: ['Amplification ratio is unmeasured.', '증폭 비율은 측정되지 않았습니다.'],
  REQUEST_VISIBILITY_NOT_PROOF: ['Missing requests do not prove reflection.', '요청 미관찰은 반사의 증거가 아닙니다.'],
  UPSTREAM_SPOOFING_UNCONFIRMED: ['Observed reflectors are not the upstream forged victim identity.', '관찰된 reflector 주소와 상류에서 위조된 피해자 주소는 다릅니다.'],
  RESPONSE_SEMANTICS_UNAVAILABLE: ['Response semantics unavailable; port and size alone are weak evidence.', '응답 의미 정보 없음: 포트·크기만으로 판단할 수 없습니다.'],
  SHARED_PROFILE_AND_PACKET_TIMING: ['At least three sources share a packet profile and three timed buckets in a ten-second window.', '최소 3개 source가 10초 구간의 3개 시간 버킷에서 패킷 프로파일을 공유합니다.'],
  NO_SHARED_TEMPORAL_PROFILE: ['Required shared temporal profile was not established.', '필요한 공통 시간 프로파일을 확인하지 못했습니다.'],
  COMPONENT_ASSESSMENTS: ['Mixed components; no shared actor inferred.', '혼합 구성요소: 공통 행위자를 추론하지 않습니다.'],
  LEGITIMATE_COORDINATION_POSSIBLE: ['Legitimate coordinated activity remains possible.', '정상적인 동기화 활동일 수 있습니다.'],
  COMPROMISE_UNCONFIRMED: ['Compromise and botnet attribution are unconfirmed.', '침해 및 봇넷 귀속은 미확인입니다.'],
  PACKET_TIMING_OR_PROFILE_UNAVAILABLE: ['Insufficient actual packet timing or shared profile evidence.', '실제 패킷 시간 또는 공통 프로파일 근거가 부족합니다.'],
  INVALID_SOURCE_ADDRESS_OBSERVED: ['Invalid multicast source address observed; not actor attribution.', '멀티캐스트 source 주소 관찰: 행위자 귀속이 아닙니다.'],
  SOURCE_VALIDATION_UNAVAILABLE: ['No independent source validation; valid-looking addresses are not proof.', '독립적인 source 검증 없음: 정상 형식 주소도 진위 증거가 아닙니다.'],
  TTL_IPID_VARIATION_NOT_PROOF: ['TTL/IP-ID variation may reflect routing, NAT, randomness or reordering; not spoofing proof.', 'TTL/IP-ID 변화는 경로·NAT·무작위화·재정렬 때문일 수 있으며 위조 증거가 아닙니다.'],
  EVIDENCE_COVERAGE_LIMITED: ['Evidence coverage is limited; coordination claims withheld.', '근거 범위가 제한되어 조율 주장을 유보합니다.'],
};
