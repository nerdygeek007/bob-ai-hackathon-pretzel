import React, { ReactNode } from 'react';

export interface Column<T> {
  header: string;
  accessor?: keyof T;
  render?: (row: T, index: number) => ReactNode;
  className?: string;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  onRowClick?: (row: T) => void;
  selectedRowId?: string;
  rowIdKey?: keyof T;
  emptyMessage?: string;
}

export function DataTable<T>({
  columns,
  data,
  onRowClick,
  selectedRowId,
  rowIdKey,
  emptyMessage = 'No records found',
}: DataTableProps<T>) {
  return (
    <div className="w-full overflow-x-auto">
      <table className="w-full text-left border-collapse text-xs font-mono">
        <thead>
          <tr className="border-b border-[#1f293d] bg-slate-900/60 text-slate-400 text-[11px] uppercase tracking-wider font-semibold">
            {columns.map((col, idx) => (
              <th key={idx} className={`py-2.5 px-3.5 ${col.className || ''}`}>
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-[#1e293b]/60">
          {data.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="py-8 text-center text-slate-500 italic">
                {emptyMessage}
              </td>
            </tr>
          ) : (
            data.map((row, rowIdx) => {
              const rowId = rowIdKey ? String(row[rowIdKey]) : String(rowIdx);
              const isSelected = selectedRowId === rowId;
              return (
                <tr
                  key={rowIdx}
                  onClick={() => onRowClick && onRowClick(row)}
                  className={`transition-colors ${
                    onRowClick ? 'cursor-pointer hover:bg-slate-800/60' : ''
                  } ${isSelected ? 'bg-cyan-950/40 border-l-2 border-cyan-400' : 'bg-transparent'}`}
                >
                  {columns.map((col, colIdx) => (
                    <td key={colIdx} className={`py-2.5 px-3.5 text-slate-300 ${col.className || ''}`}>
                      {col.render
                        ? col.render(row, rowIdx)
                        : col.accessor
                        ? String(row[col.accessor] ?? '—')
                        : null}
                    </td>
                  ))}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}
