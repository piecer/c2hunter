import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from './api';

type PolicyList<T> = T[] | { items: T[]; page?: number; page_size?: number; total?: number };
export function usePolicyPage<T>(resource: string) {
  const [page, setPage] = useState(1);
  const query = useQuery<PolicyList<T>, Error>({ queryKey: [resource, page], queryFn: () => api.get(`/${resource}?page=${page}&page_size=10`) });
  const data = query.data;
  const server = data && !Array.isArray(data) && data.page !== undefined && data.page_size !== undefined && data.total !== undefined;
  const all = Array.isArray(data) ? data : data?.items ?? [];
  const total = server ? data.total! : all.length;
  const pages = Math.max(1, Math.ceil(total / (server ? data.page_size! : 10)));
  const rows = server ? all : all.slice((page - 1) * 10, page * 10);
  return { query, rows, page, pages, total, setPage };
}
