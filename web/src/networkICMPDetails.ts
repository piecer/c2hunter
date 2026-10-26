// Closed, callback-free ICMP detail projection; raw saved evidence is untouched.
export type ICMPQuote = { source_ip: string | null; destination_ip: string | null; source_port: number | null; destination_port: number | null; protocol: string | null };
export type ICMPSample = { reporter_ip: string; protocol: string; type: number; code: number; quoted_flow: ICMPQuote | null; time: string; packet_reference: null };
export type ICMPDetails = { version: 'network-icmp-details-v1'; samples: ICMPSample[]; omitted_event_details: number };
export type ICMPResult = { state: 'absent' | 'invalid' } | { state: 'valid'; value: ICMPDetails };
const own = (o: object, key: PropertyKey) => { const d = Object.getOwnPropertyDescriptor(o, key); return d?.enumerable && Object.hasOwn(d, 'value') ? d : undefined; };
const closed = (v: unknown, keys: string[]): Record<string, unknown> | undefined => {
  if (!v || typeof v !== 'object' || Array.isArray(v) || ![Object.prototype, null].includes(Object.getPrototypeOf(v)) || Reflect.ownKeys(v).length !== keys.length || !keys.every(k => own(v, k))) return;
  return v as Record<string, unknown>;
};
const count = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
const port = (v: unknown) => v === null || (count(v) && v <= 65535);
const ipv4 = (s: string) => { const p = s.split('.'); return p.length === 4 && p.every(x => /^(0|[1-9][0-9]{0,2})$/.test(x) && Number(x) <= 255); };
function ip(v: unknown): v is string {
  if (typeof v !== 'string' || !v.length || v.length > 45) return false;
  if (!v.includes(':')) return ipv4(v);
  let s = v;
  if (s.includes('.')) { const last = s.lastIndexOf(':'); if (!ipv4(s.slice(last + 1))) return false; s = s.slice(0, last + 1) + '0:0'; }
  if (!/^[0-9a-fA-F:]+$/.test(s) || s.includes(':::')) return false;
  const halves = s.split('::');
  if (halves.length > 2) return false;
  const parts = halves.flatMap(h => h ? h.split(':') : []);
  return parts.every(p => /^[0-9a-fA-F]{1,4}$/.test(p)) && (halves.length === 2 ? parts.length < 8 : parts.length === 8);
}
function time(v: unknown): v is string {
  if (typeof v !== 'string' || v.length > 32 || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{6})?\+00:00$/.test(v)) return false;
  const [y, m, d, h, min, sec] = [v.slice(0,4),v.slice(5,7),v.slice(8,10),v.slice(11,13),v.slice(14,16),v.slice(17,19)].map(Number);
  const date = new Date(0); date.setUTCFullYear(y,m-1,d); date.setUTCHours(h,min,sec,0);
  return y >= 1 && date.getUTCFullYear() === y && date.getUTCMonth() === m-1 && date.getUTCDate() === d && date.getUTCHours() === h && date.getUTCMinutes() === min && date.getUTCSeconds() === sec;
}
export function parseICMPDetails(example: object, eventCount: number, pattern: string): ICMPResult {
  if (!('icmp_details' in example)) return { state: 'absent' };
  const invalid: ICMPResult = { state: 'invalid' };
  const d = closed(own(example, 'icmp_details')?.value, ['version','samples','omitted_event_details']);
  if (pattern !== 'icmp_errors' || !d || d.version !== 'network-icmp-details-v1' || !count(d.omitted_event_details) || !count(eventCount)) return invalid;
  const rows = d.samples;
  if (!Array.isArray(rows) || rows.length > 4 || Object.getPrototypeOf(rows) !== Array.prototype || Reflect.ownKeys(rows).length !== rows.length + 1 || eventCount - rows.length !== d.omitted_event_details) return invalid;
  const samples: ICMPSample[] = [];
  for (let i = 0; i < rows.length; i++) {
    const s = closed(own(rows,String(i))?.value, ['reporter_ip','protocol','type','code','quoted_flow','time','packet_reference']);
    if (!s || !ip(s.reporter_ip) || typeof s.protocol !== 'string' || !['ICMP','ICMPV6'].includes(s.protocol) || !count(s.type) || s.type > 255 || !count(s.code) || s.code > 255 || !time(s.time) || s.packet_reference !== null) return invalid;
    let quote: ICMPQuote | null = null;
    if (s.quoted_flow !== null) {
      const q = closed(s.quoted_flow,['source_ip','destination_ip','source_port','destination_port','protocol']);
      if (!q || (q.source_ip !== null && !ip(q.source_ip)) || (q.destination_ip !== null && !ip(q.destination_ip)) || !port(q.source_port) || !port(q.destination_port) || (q.protocol !== null && (typeof q.protocol !== 'string' || !['TCP','UDP','ICMP','ICMPV6'].includes(q.protocol)))) return invalid;
      quote = { source_ip:q.source_ip as string|null, destination_ip:q.destination_ip as string|null, source_port:q.source_port as number|null, destination_port:q.destination_port as number|null, protocol:q.protocol as string|null };
    }
    samples.push({ reporter_ip:s.reporter_ip, protocol:s.protocol, type:s.type, code:s.code, quoted_flow:quote, time:s.time, packet_reference:null });
  }
  return { state:'valid', value:{version:'network-icmp-details-v1',samples,omitted_event_details:d.omitted_event_details} };
}
