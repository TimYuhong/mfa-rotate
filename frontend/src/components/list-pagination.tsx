import { ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "./ui/button";
import type { PageSize } from "../list-page";

type Props = {
  label: string;
  page: number;
  pageSize: PageSize;
  pageCount: number;
  total: number;
  onPageChange: (page: number) => void;
  onPageSizeChange: (size: PageSize) => void;
};

// Business pagination composed from the existing shadcn Button and native select.
export function ListPagination({ label, page, pageSize, pageCount, total, onPageChange, onPageSizeChange }: Props) {
  return (
    <nav className="list-pagination" aria-label={`${label}分页`}>
      <span className="pagination-total">共 {total} 条</span>
      <div className="pagination-controls">
        <label className="page-size">
          <span>每页</span>
          <select value={pageSize} aria-label={`${label}每页条数`}
            onChange={event => onPageSizeChange(Number(event.target.value) as PageSize)}>
            <option value={10}>10 条</option>
            <option value={20}>20 条</option>
            <option value={50}>50 条</option>
          </select>
        </label>
        <div className="page-navigation">
          <Button variant="plain" size="icon" aria-label="上一页" disabled={page <= 1}
            onClick={() => onPageChange(page - 1)}><ChevronLeft size={16} /></Button>
          <span className="page-number" role="status">第 {page} / {pageCount} 页</span>
          <Button variant="plain" size="icon" aria-label="下一页" disabled={page >= pageCount}
            onClick={() => onPageChange(page + 1)}><ChevronRight size={16} /></Button>
        </div>
      </div>
    </nav>
  );
}
