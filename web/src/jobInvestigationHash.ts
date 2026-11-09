/** Bounded synchronous SHA-256 for immutable pool commitments, not authentication.
 * No native crypto dependency: insecure-context browsers still validate bytes.
 */
export function jobSHA256(text: string): string {
  const bytes = new TextEncoder().encode(text);
  if (bytes.length > 262144) throw new Error('Hash input limit');
  const k: number[] = [], h: number[] = [];
  for (let n = 2; k.length < 64; n++) {
    let prime = true;
    for (let d = 2; d * d <= n; d++) if (n % d === 0) { prime = false; break; }
    if (prime) { if (h.length < 8) h.push((Math.sqrt(n) % 1 * 4294967296) | 0); k.push((Math.cbrt(n) % 1 * 4294967296) | 0); }
  }
  const data = new Uint8Array(Math.ceil((bytes.length + 9) / 64) * 64);
  data.set(bytes); data[bytes.length] = 128;
  new DataView(data.buffer).setUint32(data.length - 4, bytes.length * 8);
  const w = new Int32Array(64), view = new DataView(data.buffer);
  const rotate = (x: number, n: number) => x >>> n | x << (32 - n);
  for (let offset = 0; offset < data.length; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getInt32(offset + i * 4);
    for (let i = 16; i < 64; i++) { const a = w[i - 15], b = w[i - 2]; w[i] = w[i - 16] + (rotate(a, 7) ^ rotate(a, 18) ^ a >>> 3) + w[i - 7] + (rotate(b, 17) ^ rotate(b, 19) ^ b >>> 10); }
    let [a,b,c,d,e,f,g,j] = h;
    for (let i = 0; i < 64; i++) {
      const t = j + (rotate(e,6)^rotate(e,11)^rotate(e,25)) + ((e&f)^(~e&g)) + k[i] + w[i];
      const u = (rotate(a,2)^rotate(a,13)^rotate(a,22)) + ((a&b)^(a&c)^(b&c));
      j=g;g=f;f=e;e=(d+t)|0;d=c;c=b;b=a;a=(t+u)|0;
    }
    [a,b,c,d,e,f,g,j].forEach((x,i)=> { h[i]=(h[i]+x)|0; });
  }
  return h.map(x=>(x>>>0).toString(16).padStart(8,'0')).join('');
}
