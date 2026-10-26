import { ChevronDown, ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "./ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuTrigger } from "./ui/dropdown-menu";
import { DialogGlass } from "./dialog-glass";
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

// Business pagination: Radix owns the nonmodal radio menu and keyboard/focus behavior.
export function ListPagination({ label, page, pageSize, pageCount, total, onPageChange, onPageSizeChange }: Props) {
  return (
    <nav className="list-pagination" aria-label={`${label}分页`}>
      <span className="pagination-total">共 {total} 条</span>
      <div className="pagination-controls">
        <div className="page-size">
          <span>每页</span>
          <DropdownMenu modal={false}>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" className="page-size-trigger" aria-label={`${label}每页条数`} aria-description={`当前 ${pageSize} 条`}>
                <span>{pageSize} 条</span><ChevronDown size={14} aria-hidden="true" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent className="glass-menu" aria-label={`${label}每页条数选项`} align="end" sideOffset={8} collisionPadding={12}>
              <DialogGlass variant="menu" />
              <DropdownMenuRadioGroup value={String(pageSize)} onValueChange={value => onPageSizeChange(Number(value) as PageSize)}>
                {[10, 20, 50].map(value => <DropdownMenuRadioItem key={value} value={String(value)}>{value} 条</DropdownMenuRadioItem>)}
              </DropdownMenuRadioGroup>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
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
