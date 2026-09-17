import React from 'react';

export interface Column<T> {
  key: string;
  header: React.ReactNode;
  width?: string;
  render?: (item: T) => React.ReactNode;
}

export interface TableProps<T> {
  columns: Column<T>[];
  data: T[];
  keyExtractor: (item: T) => string;
  emptyText?: string;
  onRowClick?: (item: T) => void;
  selectedKeys?: Set<string>;
}

export function Table<T>({
  columns,
  data,
  keyExtractor,
  emptyText = 'No items found.',
  onRowClick,
  selectedKeys,
}: TableProps<T>): React.ReactElement {
  if (data.length === 0) {
    return (
      <div
        style={{
          padding: '32px',
          textAlign: 'center',
          color: 'var(--text-muted)',
          fontSize: '13px',
          border: '1px solid var(--border-color)',
          borderRadius: '6px',
          backgroundColor: 'var(--bg-secondary)',
        }}
      >
        {emptyText}
      </div>
    );
  }

  return (
    <div
      style={{
        border: '1px solid var(--border-color)',
        borderRadius: '6px',
        overflow: 'hidden',
        backgroundColor: 'var(--bg-secondary)',
      }}
    >
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border-color)', backgroundColor: 'rgba(0,0,0,0.2)' }}>
            {columns.map((col) => (
              <th
                key={col.key}
                style={{
                  padding: '10px 14px',
                  textAlign: 'left',
                  fontWeight: 600,
                  color: 'var(--text-secondary)',
                  width: col.width,
                  fontSize: '12px',
                }}
              >
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((item) => {
            const rowKey = keyExtractor(item);
            const isSelected = selectedKeys?.has(rowKey);
            return (
              <tr
                key={rowKey}
                onClick={() => onRowClick?.(item)}
                style={{
                  borderBottom: '1px solid var(--border-subtle)',
                  cursor: onRowClick ? 'pointer' : 'default',
                  backgroundColor: isSelected ? 'rgba(37, 99, 235, 0.1)' : 'transparent',
                  transition: 'background-color 0.1s ease',
                }}
              >
                {columns.map((col) => {
                  const val = (item as Record<string, unknown>)[col.key];
                  return (
                    <td
                      key={col.key}
                      style={{
                        padding: '10px 14px',
                        color: 'var(--text-primary)',
                        verticalAlign: 'middle',
                      }}
                    >
                      {col.render ? col.render(item) : String(val ?? '')}
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
