/** Preserve the server's 50-row default; never enlarge it to hide missing navigation. */
export function sensorPagePath(path: string, page: number, filters: Record<string, string> = {}) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) if (value) params.set(key, value);
  if (page !== 1 || params.size) { params.set('page', String(page)); params.set('page_size', '50'); }
  return `${path}${params.size ? `?${params}` : ''}`;
}
