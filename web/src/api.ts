export class ApiError extends Error {
  constructor(message: string, public status: number, public code = 'HTTP_ERROR', public details?: unknown) { super(message); this.name = 'ApiError'; }
}

function invalidateAuthentication(response: Response): void {
  if (response.status !== 401) return;
  localStorage.removeItem('c2hunter-token');
  window.dispatchEvent(new Event('c2hunter-auth-invalid'));
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = localStorage.getItem('c2hunter-token');
  const headers = new Headers(init.headers);
  headers.set('accept', 'application/json');
  if (init.body && !headers.has('content-type')) headers.set('content-type', 'application/json');
  if (token) headers.set('authorization', `Bearer ${token}`);
  const response = await fetch(`/api/v1${path}`, { ...init, headers: Object.fromEntries(headers.entries()) });
  // Read a clone so repeated test adapters and cache layers that return the same
  // Response object cannot make a later request lose the structured error body.
  const body = response.status === 204 ? undefined : await response.clone().json().catch(() => undefined);
  if (!response.ok) {
    invalidateAuthentication(response);
    const envelope = body?.error ?? body;
    throw new ApiError(envelope?.message ?? `Request failed (${response.status})`, response.status, envelope?.code, envelope?.details);
  }
  return body as T;
}

async function download(path: string, fallbackFilename: string): Promise<void> {
  const token = localStorage.getItem('c2hunter-token');
  const headers: Record<string, string> = { accept: 'application/vnd.tcpdump.pcap' };
  if (token) headers.authorization = `Bearer ${token}`;
  const response = await fetch(`/api/v1${path}`, { headers });
  if (!response.ok) {
    invalidateAuthentication(response);
    const body = await response.clone().json().catch(() => undefined);
    const envelope = body?.error ?? body;
    throw new ApiError(envelope?.message ?? `Request failed (${response.status})`, response.status, envelope?.code, envelope?.details);
  }
  const disposition = response.headers.get('content-disposition') ?? '';
  const match = disposition.match(/filename="([A-Za-z0-9._-]+)"/);
  const filename = match?.[1] ?? fallbackFilename;
  const objectUrl = URL.createObjectURL(await response.blob());
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
    const abort = () => request.abort();
    const cleanup = () => signal?.removeEventListener('abort', abort);
    request.open('PUT', `/api/v1${path}`);
    request.setRequestHeader('accept', 'application/json');
    request.setRequestHeader('content-type', contentType);
    const token = localStorage.getItem('c2hunter-token');
    if (token) request.setRequestHeader('authorization', `Bearer ${token}`);
    request.upload.onprogress = event => {
      if (event.lengthComputable) onProgress({ loaded: event.loaded, total: event.total });
    };
    request.onload = () => {
      cleanup();
      let parsed: unknown;
      try { parsed = request.responseText ? JSON.parse(request.responseText) : undefined; } catch { parsed = undefined; }
      if (request.status >= 200 && request.status < 300) {
        resolve(parsed as T);
        return;
      }
      if (request.status === 401) {
        localStorage.removeItem('c2hunter-token');
        window.dispatchEvent(new Event('c2hunter-auth-invalid'));
      }
      const envelope = (parsed as { error?: { code?: string; message?: string; details?: unknown } } | undefined)?.error;
      reject(new ApiError(envelope?.message ?? `Request failed (${request.status})`, request.status, envelope?.code, envelope?.details));
    };
    request.onerror = () => { cleanup(); reject(new ApiError('Upload transport failed', 0, 'UPLOAD_TRANSPORT_ERROR')); };
    request.onabort = () => { cleanup(); reject(new DOMException('Upload aborted', 'AbortError')); };
    if (signal?.aborted) { request.abort(); return; }
    signal?.addEventListener('abort', abort, { once: true });
    request.send(body);
  });
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) => request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) }),
  put: <T>(path: string, body?: unknown) => request<T>(path, { method: 'PUT', body: body === undefined ? undefined : JSON.stringify(body) }),
  patch: <T>(path: string, body?: unknown) => request<T>(path, { method: 'PATCH', body: body === undefined ? undefined : JSON.stringify(body) }),
  upload: <T>(path: string, body: Blob, contentType = 'application/octet-stream') => request<T>(path, { method: 'POST', body, headers: { 'content-type': contentType } }),
  uploadWithProgress,
  download,
  delete: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
};
