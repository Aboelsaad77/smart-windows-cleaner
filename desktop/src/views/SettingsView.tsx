import React from 'react';
import { useApp } from '../state/AppContext';
import { Card } from '../design-system/Card';
import { Badge } from '../design-system/Badge';
import { Settings as SettingsIcon, ShieldCheck } from 'lucide-react';

export const SettingsView: React.FC = () => {
  const { settings } = useApp();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <div>
        <h1 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
          Settings & Policies
        </h1>
        <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
          Configure safety parameters, retention periods, and path exclusions.
        </p>
      </div>

      <Card
        title="Quarantine Retention Policy"
        subtitle="Automatic purging timeline for quarantined files"
        actions={<SettingsIcon size={16} color="var(--text-muted)" />}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
              Retention Window
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              Files remain safely in the vault before becoming eligible for permanent purge.
            </div>
          </div>
          <Badge variant="info">
            {settings?.quarantine_retention_days ?? 7} Days
          </Badge>
        </div>
      </Card>

      <Card
        title="Excluded Protected Directories"
        subtitle="Paths automatically bypassed and protected by default"
        actions={<ShieldCheck size={16} color="#10b981" />}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {settings?.excluded_paths.map((path) => (
            <div
              key={path}
              style={{
                fontFamily: 'monospace',
                fontSize: '12px',
                padding: '6px 10px',
                backgroundColor: 'rgba(0,0,0,0.2)',
                borderRadius: '4px',
                border: '1px solid var(--border-color)',
                color: 'var(--text-secondary)',
              }}
            >
              {path}
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
};
