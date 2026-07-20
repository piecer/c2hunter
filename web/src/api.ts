export class ApiError extends Error {
  constructor(message: string, public status: number, public code = 'HTTP_ERROR', public details?: unknown) { super(message); this.name = 'ApiError'; }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = localStorage.getItem('c2hunter-token');
  const headers = new Headers(init.headers);
  headers.set('accept', 'application/json');
  if (init.body) headers.set('content-type', 'application/json');
  if (token) headers.set('authorization', `Bearer ${token}`);
  const response = await fetch(`/api/v1${path}`, { ...init, headers: Object.fromEntries(headers.entries()) });
  // Read a clone so repeated test adapters and cache layers that return the same
  // Response object cannot make a later request lose the structured error body.
  const body = response.status === 204 ? undefined : await response.clone().json().catch(() => undefined);
  if (!response.ok) {
    const envelope = body?.error ?? body;
    throw new ApiError(envelope?.message ?? `Request failed (${response.status})`, response.status, envelope?.code, envelope?.details);
  }
  return body as T;
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) => request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) }),
  put: <T>(path: string, body?: unknown) => request<T>(path, { method: 'PUT', body: body === undefined ? undefined : JSON.stringify(body) }),
  delete: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
};
