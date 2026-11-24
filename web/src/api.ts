import { authenticationHeaders, captureAuthentication, currentAuthentication, invalidateAuthentication } from './authentication';
import { readBoundedJSON } from './investigationTransport';

export class ApiError extends Error {
  constructor(message: string, public status: number, public code = 'HTTP_ERROR', public details?: unknown) { super(message); this.name = 'ApiError'; }
}

async function request<T>(path: string, init: RequestInit = {}, onStatus?: (status: number) => void): Promise<T> {
  const authority = captureAuthentication();
  const headers = authenticationHeaders(authority, init.headers);
  headers.set('accept', 'application/json');
  if (init.body && !headers.has('content-type')) headers.set('content-type', 'application/json');
  const response = await fetch(`/api/v1${path}`, { ...init, credentials: 'same-origin', redirect: 'error', headers: Object.fromEntries(headers.entries()) });
  invalidateAuthentication(response.status, authority, init.signal);
  onStatus?.(response.status);
  // Read a clone so repeated test adapters and cache layers that return the same
  // Response object cannot make a later request lose the structured error body.
  const body = response.status === 204 ? undefined : await response.clone().json().catch(() => undefined);
  if (!response.ok) {
    const envelope = body?.error ?? body;
    throw new ApiError(envelope?.message ?? `Request failed (${response.status})`, response.status, envelope?.code, envelope?.details);
  }
  return body as T;
}

async function download(path: string, fallbackFilename: string): Promise<void> {
  const authority = captureAuthentication();
  const headers = authenticationHeaders(authority, { accept: 'application/vnd.tcpdump.pcap' });
  const response = await fetch(`/api/v1${path}`, { headers: Object.fromEntries(headers.entries()), credentials: 'same-origin', redirect: 'error' });
  if (!response.ok) {
    invalidateAuthentication(response.status, authority);
    const body = await response.clone().json().catch(() => undefined);
    const envelope = body?.error ?? body;
    throw new ApiError(envelope?.message ?? `Request failed (${response.status})`, response.status, envelope?.code, envelope?.details);
  }
  const disposition = response.headers.get('content-disposition') ?? '';
  const match = disposition.match(/filename="([A-Za-z0-9._-]+)"/);
  const filename = match?.[1] ?? fallbackFilename;
  const blob = await response.blob();
  if (!currentAuthentication(authority)) return;
  const objectUrl = URL.createObjectURL(blob);
  try {
    const anchor = document.createElement('a');
    anchor.href = objectUrl;
    anchor.download = filename;
    anchor.click();
  } finally {
    URL.revokeObjectURL(objectUrl);
  }
}

function uploadWithProgress<T>(
  path: string,
  body: Blob,
  contentType: string,
  onProgress: (progress: { loaded: number; total: number }) => void,
  signal?: AbortSignal,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const request = new XMLHttpRequest();
    let settled = false;
    const abort = () => request.abort();
    const cleanup = () => signal?.removeEventListener('abort', abort);
    request.open('PUT', `/api/v1${path}`);
    request.setRequestHeader('accept', 'application/json');
    request.setRequestHeader('content-type', contentType);
    const authority = captureAuthentication();
    request.withCredentials = true;
    authenticationHeaders(authority).forEach((value, key) => request.setRequestHeader(key, value));
    request.upload.onprogress = event => {
      if (event.lengthComputable) onProgress({ loaded: event.loaded, total: event.total });
    };
    request.onload = () => {
      if (settled) return;
      settled = true;
      cleanup();
      let parsed: unknown;
      try { parsed = request.responseText ? JSON.parse(request.responseText) : undefined; } catch { parsed = undefined; }
      if (request.status >= 200 && request.status < 300) {
        resolve(parsed as T);
        return;
      }
      invalidateAuthentication(request.status, authority, signal);
      const envelope = (parsed as { error?: { code?: string; message?: string; details?: unknown } } | undefined)?.error;
      reject(new ApiError(envelope?.message ?? `Request failed (${request.status})`, request.status, envelope?.code, envelope?.details));
    };
    request.onerror = () => { settled = true; cleanup(); reject(new ApiError('Upload transport failed', 0, 'UPLOAD_TRANSPORT_ERROR')); };
    request.onabort = () => { settled = true; cleanup(); reject(new DOMException('Upload aborted', 'AbortError')); };
    if (signal?.aborted) { request.abort(); return; }
    signal?.addEventListener('abort', abort, { once: true });
    request.send(body);
  });
}

async function boundedRequest(path: string, init: RequestInit = {}, onHeaders?: (headers: Headers) => void): Promise<unknown> {
  const authority = captureAuthentication();
  const headers = authenticationHeaders(authority, init.headers);
  headers.set('accept', 'application/json');
  if (init.body) headers.set('content-type', 'application/json');
  const response = await fetch(`/api/v1${path}`, { ...init, credentials: 'same-origin', redirect: 'error', headers: Object.fromEntries(headers.entries()) });
  // Keep the existing authentication invalidation flow even on malformed errors.
  invalidateAuthentication(response.status, authority, init.signal);
  onHeaders?.(response.headers);
  const body = await readBoundedJSON(response);
  if (!response.ok) {
    const error = body && typeof body === 'object' && 'error' in body ? body.error : body;
    const code = error && typeof error === 'object' && 'code' in error && typeof error.code === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(error.code) ? error.code : 'HTTP_ERROR';
    // Do not render arbitrary driver/provider text. The safe code remains visible.
    throw new ApiError(`Investigation request failed (${response.status}): ${code}`, response.status, code);
  }
  return body;
}

export const api = {
  // Preserve DELETE status as well as body for target-specific policy ACK contracts.
  deleteReceipt: async (path: string): Promise<{ status: number; body: unknown }> => {
    let status = 0;
    const body = await request<unknown>(path, { method: 'DELETE' }, value => { status = value; });
    return { status, body };
  },
  boundedRequest,
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) => request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) }),
  put: <T>(path: string, body?: unknown) => request<T>(path, { method: 'PUT', body: body === undefined ? undefined : JSON.stringify(body) }),
  patch: <T>(path: string, body?: unknown) => request<T>(path, { method: 'PATCH', body: body === undefined ? undefined : JSON.stringify(body) }),
  upload: <T>(path: string, body: Blob, contentType = 'application/octet-stream') => request<T>(path, { method: 'POST', body, headers: { 'content-type': contentType } }),
  uploadWithProgress,
  download,
  delete: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
};
