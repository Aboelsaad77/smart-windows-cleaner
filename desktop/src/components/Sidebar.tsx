import React from 'react';
import { useApp, NavigationRoute } from '../state/AppContext';
import {
  LayoutDashboard,
  Search,
  ListFilter,
  ShieldCheck,
  HardDrive,
  FileText,
  Settings,
} from 'lucide-react';

interface NavItem {
  id: NavigationRoute;
  label: string;
  icon: React.ReactNode;
  badge?: React.ReactNode;
}

export const Sidebar: React.FC = () => {
  const { currentRoute, setCurrentRoute, scanStatus, systemStatus } = useApp();

  const isScanning = scanStatus?.state === 'scanning';
  const quarantineCount = systemStatus?.quarantine_item_count ?? 0;

  const navItems: NavItem[] = [
    { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={18} /> },
    {
      id: 'scan',
      label: 'Scan',
      icon: <Search size={18} />,
      badge: isScanning ? (
        <span
          style={{
            fontSize: '10px',
            padding: '1px 6px',
            backgroundColor: '#2563eb',
            color: '#fff',
            borderRadius: '9999px',
            fontWeight: 600,
          }}
        >
          LIVE
        </span>
      ) : undefined,
    },
    { id: 'results', label: 'Results', icon: <ListFilter size={18} /> },
    {
      id: 'quarantine',
      label: 'Quarantine',
      icon: <ShieldCheck size={18} />,
      badge:
        quarantineCount > 0 ? (
          <span
            style={{
              fontSize: '10px',
              padding: '1px 6px',
              backgroundColor: 'var(--bg-tertiary)',
              color: 'var(--text-secondary)',
              borderRadius: '9999px',
              fontWeight: 600,
            }}
          >
            {quarantineCount}
          </span>
        ) : undefined,
    },
    { id: 'storage', label: 'Storage', icon: <HardDrive size={18} /> },
    { id: 'logs', label: 'Logs & Audit', icon: <FileText size={18} /> },
    { id: 'settings', label: 'Settings', icon: <Settings size={18} /> },
  ];

  return (
    <aside
      style={{
        width: '210px',
        backgroundColor: 'var(--bg-secondary)',
        borderRight: '1px solid var(--border-color)',
        display: 'flex',
        flexDirection: 'column',
        padding: '12px 8px',
        gap: '4px',
        userSelect: 'none',
        flexShrink: 0,
      }}
    >
      <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', padding: '6px 12px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
        Workspace
      </div>

      {navItems.map((item) => {
        const isActive = currentRoute === item.id;
        return (
          <button
            key={item.id}
            onClick={() => setCurrentRoute(item.id)}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '9px 12px',
              borderRadius: '6px',
              border: 'none',
              backgroundColor: isActive ? 'var(--bg-tertiary)' : 'transparent',
              color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
              fontWeight: isActive ? 600 : 500,
              fontSize: '13px',
              cursor: 'pointer',
              transition: 'background-color 0.15s ease, color 0.15s ease',
              textAlign: 'left',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{ color: isActive ? '#3b82f6' : 'var(--text-muted)' }}>{item.icon}</span>
              <span>{item.label}</span>
            </div>
            {item.badge}
          </button>
        );
      })}
    </aside>
  );
};
