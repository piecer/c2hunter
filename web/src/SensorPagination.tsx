export type SensorPage<T> = { items: T[]; page?: number; page_size?: number; total?: number } | T[];

export function SensorPagination<T>({ data, onPage, label = 'Pages' }: { data?: SensorPage<T>; onPage: (page: number) => void; label?: string }) {
  if (!data || Array.isArray(data) || data.total === undefined || !data.page_size) return null;
  const page = data.page ?? 1;
  const last = Math.max(1, Math.ceil(data.total / data.page_size));
  return <nav aria-label={label} className="sensor-pagination"><span>Page {page} of {last} · {data.total} records</span><button type="button" disabled={page <= 1} onClick={() => onPage(1)}>First page</button><button type="button" disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous page</button><button type="button" disabled={page >= last} onClick={() => onPage(page + 1)}>Next page</button><button type="button" disabled={page >= last} onClick={() => onPage(last)}>Last page</button></nav>;
}
