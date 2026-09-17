import React from 'react';
import { useApp } from '../state/AppContext';
import { StatusIndicator } from '../design-system/StatusIndicator';
import { Badge } from '../design-system/Badge';
import { Button } from '../design-system/Button';
import { Shield, ShieldAlert, Sparkles } from 'lucide-react';

export const AppHeader: React.FC = () => {
  const { systemStatus, connectionStatus, openElevationModal } = useApp();

  return (
    <header
      style={{
        height: '48px',
        backgroundColor: 'var(--bg-secondary)',
        borderBottom: '1px solid var(--border-color)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 16px',
        userSelect: 'none',
        flexShrink: 0,
      }}
    >
      {/* Brand Identity */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        <div
          style={{
            width: '28px',
            height: '28px',
            borderRadius: '6px',
            backgroundColor: '#2563eb',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#ffffff',
            boxShadow: '0 2px 4px rgba(0,0,0,0.2)',
          }}
        >
          <Sparkles size={16} />
        </div>
        <div>
          <span style={{ fontSize: '14px', fontWeight: 700, letterSpacing: '-0.01em', color: 'var(--text-primary)' }}>
            Smart Cleaner
          </span>
          <span
            style={{
              fontSize: '10px',
              marginLeft: '6px',
              padding: '1px 5px',
              borderRadius: '4px',
              backgroundColor: 'var(--bg-tertiary)',
              color: 'var(--text-muted)',
              fontFamily: 'monospace',
            }}
          >
            v1.0.0 (Core Native)
          </span>
        </div>
      </div>

      {/* Status & Privileges */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        <StatusIndicator status={connectionStatus} />

        <div style={{ height: '18px', width: '1px', backgroundColor: 'var(--border-color)' }} />

        {systemStatus?.is_elevated ? (
          <Badge variant="safe" title="Running with full Windows Administrator elevation">
            <Shield size={12} style={{ marginRight: '2px' }} />
            Administrator (UAC Active)
          </Badge>
        ) : (
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Badge variant="elevation" title="Running with standard user permissions">
              <ShieldAlert size={12} style={{ marginRight: '2px' }} />
              Standard User
            </Badge>
            <Button
              variant="outline"
              size="sm"
              onClick={() => openElevationModal()}
              title="Request administrator elevation for protected Windows paths"
            >
              Elevate
            </Button>
          </div>
        )}
      </div>
    </header>
  );
};
