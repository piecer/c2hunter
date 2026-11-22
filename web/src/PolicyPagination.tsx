export default function PolicyPagination({ page, pages, total, setPage }: { page: number; pages: number; total: number; setPage: (page: number) => void }) {
  return <nav className="policy-pagination" aria-label="Policy pages"><button type="button" className="secondary" aria-label="Previous policy page" disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</button><span>Page {page} / {pages} · {total} records</span><button type="button" className="secondary" aria-label="Next policy page" disabled={page >= pages} onClick={() => setPage(page + 1)}>Next</button></nav>;
}
