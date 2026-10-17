// Native Python ISO timestamps: four-digit calendar year, seconds, optional
// 1–6 fractional digits, and an explicit Z or ±HH:MM zone. Not general ISO parsing.
export function parseDDoSTimestamp(value: unknown): bigint | null {
  if (typeof value !== 'string' || value.length < 20 || value.length > 32) return null;
  const parts = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|([+-])(\d{2}):(\d{2}))$/.exec(value);
  if (!parts) return null;
  const [, y, mo, d, h, mi, s, fraction, zone, sign, oh, om] = parts;
  const year = Number(y), month = Number(mo), day = Number(d);
  const hour = Number(h), minute = Number(mi), second = Number(s);
  const offsetHour = zone === 'Z' ? 0 : Number(oh), offsetMinute = zone === 'Z' ? 0 : Number(om);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (year < 1 || month < 1 || month > 12 || day < 1 || day > days[month - 1]
    || hour > 23 || minute > 59 || second > 59 || offsetHour > 23 || offsetMinute > 59) return null;
  // Components are validated before Date can normalize them. setUTCFullYear
  // avoids Date.UTC's 1900 remapping of years 00–99. Milliseconds in this bounded
  // calendar range are exact integers; add fractions only after converting.
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, 0);
  const offset = (offsetHour * 60 + offsetMinute) * (sign === '-' ? -1 : 1);
  return BigInt(date.getTime()) * 1000n + BigInt(fraction?.padEnd(6, '0') ?? '0') - BigInt(offset) * 60000000n;
}
