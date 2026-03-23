import React from 'react';

const LEVEL_CONFIG = {
  agent: { label: 'AGENT', className: 'denial-badge denial-agent' },
  tool: { label: 'TOOL', className: 'denial-badge denial-tool' },
  scope: { label: 'SCOPE', className: 'denial-badge denial-scope' },
  resource: { label: 'RESOURCE', className: 'denial-badge denial-resource' },
};

export default function DenialIndicator({ level, reason }) {
  if (!level) return null;

  const config = LEVEL_CONFIG[level] || { label: level.toUpperCase(), className: 'denial-badge' };

  return (
    <span className={config.className} title={reason || ''}>
      {config.label}
    </span>
  );
}
