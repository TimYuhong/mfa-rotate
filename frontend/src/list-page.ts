import { useEffect, useState } from "react";

export type PageSize = 10 | 20 | 50;

export function useListPage<T>(items: T[]) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState<PageSize>(10);
  const pageCount = Math.max(1, Math.ceil(items.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  useEffect(() => setPage(previous => Math.min(previous, pageCount)), [pageCount]);

  return {
    items: items.slice((currentPage - 1) * pageSize, currentPage * pageSize),
    page: currentPage,
    pageSize,
    pageCount,
    total: items.length,
    setPage,
    setPageSize(value: PageSize) { setPageSize(value); setPage(1); },
  };
}
