export const INVESTIGATION_RESPONSE_LIMIT = 256 * 1024;

/** Count stream bytes before decoding or JSON.parse. Cancel at the first excess. */
export async function readBoundedJSON(response: Response, limit = INVESTIGATION_RESPONSE_LIMIT): Promise<unknown> {
  const advertised = response.headers.get('content-length');
  if (advertised !== null && /^\d+$/.test(advertised) && Number(advertised) > limit) {
    await response.body?.cancel();
    throw new Error('Investigation response exceeds byte limit');
  }
  if (!response.body) throw new Error('Missing investigation response body');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      length += chunk.value.byteLength;
      if (length > limit) { await reader.cancel(); throw new Error('Investigation response exceeds byte limit'); }
      chunks.push(chunk.value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { throw new Error('Invalid investigation JSON'); }
}
