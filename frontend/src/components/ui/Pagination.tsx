import React from 'react';
import Button from './Button';

export interface PaginationProps {
  page: number;
  pageSize: number;
  totalCount?: number;
  onPageChange: (page: number) => void;
  onPageSizeChange?: (size: number) => void;
}

const Pagination: React.FC<PaginationProps> = ({
  page,
  pageSize,
  totalCount,
  onPageChange,
  onPageSizeChange,
}) => {
  const totalPages = totalCount ? Math.ceil(totalCount / pageSize) : undefined;
  const hasNextPage = totalPages ? page < totalPages : true;
  const hasPrevPage = page > 1;

  return (
    <div className="flex items-center justify-between gap-4 rounded-2xl border border-soc-border bg-slate-900/50 p-4">
      <div className="flex items-center gap-4">
        <span className="text-sm text-slate-400">
          Page <span className="font-semibold text-slate-200">{page}</span>
          {totalPages && <span className="text-slate-500"> of {totalPages}</span>}
        </span>
        {totalCount !== undefined && (
          <span className="text-sm text-slate-400">
            Total: <span className="font-semibold text-slate-200">{totalCount}</span>
          </span>
        )}
        {onPageSizeChange && (
          <select
            value={pageSize}
            onChange={(e) => onPageSizeChange(Number(e.target.value))}
            className="rounded-lg border border-soc-border bg-slate-900/95 px-3 py-1.5 text-sm text-slate-100 outline-none"
          >
            <option value={10}>10 per page</option>
            <option value={25}>25 per page</option>
            <option value={50}>50 per page</option>
            <option value={100}>100 per page</option>
          </select>
        )}
      </div>
      <div className="flex gap-2">
        <Button
          variant="secondary"
          size="sm"
          onClick={() => onPageChange(page - 1)}
          disabled={!hasPrevPage}
        >
          Previous
        </Button>
        <Button
          variant="secondary"
          size="sm"
          onClick={() => onPageChange(page + 1)}
          disabled={!hasNextPage}
        >
          Next
        </Button>
      </div>
    </div>
  );
};

export default Pagination;
