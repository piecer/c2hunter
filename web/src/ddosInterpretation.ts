// Read only the bounded producer fields; never stringify/copy the public run
// envelope (which permits extras) or traverse unrelated nested metadata.
export type DDoSInterpretation = {
  schema_version: 'ddos-interpretation-v1'; kind: 'MODEL_INTERPRETATION'; language: 'ko' | 'en'; summary: string;
  risk_context: { interpretation: string; finding_ids: string[]; uncertainty: string }[];
  prioritized_checks: { priority: string; check: string; finding_ids: string[] }[];
  response_considerations: { consideration: string; finding_ids: string[]; requires_human_approval: true }[];
  limitations: string[];
};
function fail(): never { throw new Error('Invalid DDoS interpretation'); }
function field(value: unknown, key: string): unknown {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return fail();
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor && 'value' in descriptor && descriptor.enumerable ? descriptor.value : fail();
}
function text(value: unknown): string {
  // Python max_length counts code points. Reject before the bounded Unicode scan.
  if (typeof value !== 'string' || !value.length || value.length > 2400) return fail();
  let count = 0;
  for (const point of value) { void point; if (++count > 1200) return fail(); }
  return value;
}
function list<T>(value: unknown, max: number, decode: (item: unknown) => T, min = 0): T[] {
  if (!Array.isArray(value) || value.length < min || value.length > max) return fail();
  const output: T[] = [];
  for (let i = 0; i < value.length; i += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(i));
    if (!descriptor || !('value' in descriptor)) return fail();
    output.push(decode(descriptor.value));
  }
  return output;
}
function ids(value: unknown, min = 0): string[] {
  const result = list(value, 20, value => typeof value === 'string' && value.length === 21 && /^ddos-[0-9a-f]{16}$/.test(value) ? value : fail(), min);
  return new Set(result).size === result.length ? result : fail();
}
export function decodeDDoSInterpretation(value: unknown): DDoSInterpretation | undefined {
  try {
    if (field(value, 'schema_version') !== 'ddos-interpretation-v1' || field(value, 'kind') !== 'MODEL_INTERPRETATION') return undefined;
    const language = field(value, 'language');
    if (language !== 'en' && language !== 'ko') return undefined;
    return {
      schema_version: 'ddos-interpretation-v1', kind: 'MODEL_INTERPRETATION', language,
      summary: text(field(value, 'summary')),
      risk_context: list(field(value, 'risk_context'), 10, item => ({ interpretation: text(field(item, 'interpretation')), uncertainty: text(field(item, 'uncertainty')), finding_ids: ids(field(item, 'finding_ids'), 1) })),
      prioritized_checks: list(field(value, 'prioritized_checks'), 10, item => {
        const priority = field(item, 'priority');
        if (priority !== 'HIGH' && priority !== 'MEDIUM' && priority !== 'LOW') return fail();
        return { priority, check: text(field(item, 'check')), finding_ids: ids(field(item, 'finding_ids')) };
      }),
      response_considerations: list(field(value, 'response_considerations'), 10, item => {
        if (field(item, 'requires_human_approval') !== true) return fail();
        return { consideration: text(field(item, 'consideration')), finding_ids: ids(field(item, 'finding_ids')), requires_human_approval: true };
      }),
      limitations: list(field(value, 'limitations'), 12, text, 1),
    };
  } catch { return undefined; }
}
