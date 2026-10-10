import React from 'react';
import { SeverityLevel } from '../types';

interface RiskBadgeProps {
  severity: SeverityLevel;
  score?: number;
  size?: 'sm' | 'md' | 'lg';
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({ severity, score, size = 'md' }) => {
  const styles = {
    LOW: {
      bg: 'bg-emerald-950/70',
      text: 'text-emerald-400',
      border: 'border-emerald-700/50',
      dot: 'bg-emerald-400',
      label: 'LOW RISK',
    },
    MEDIUM: {
      bg: 'bg-amber-950/70',
      text: 'text-amber-400',
      border: 'border-amber-700/50',
      dot: 'bg-amber-400',
      label: 'MEDIUM RISK',
    },
    HIGH: {
      bg: 'bg-orange-950/70',
      text: 'text-orange-400',
      border: 'border-orange-700/50',
      dot: 'bg-orange-400',
      label: 'HIGH RISK',
    },
    CRITICAL: {
      bg: 'bg-rose-950/70',
      text: 'text-rose-400',
      border: 'border-rose-700/50',
      dot: 'bg-rose-400',
      label: 'CRITICAL THREAT',
    },
  }[severity] || {
    bg: 'bg-slate-900',
    text: 'text-slate-400',
    border: 'border-slate-700',
    dot: 'bg-slate-400',
    label: severity,
  };

  const sizeClasses = {
    sm: 'text-[10px] px-2 py-0.5',
    md: 'text-xs px-2.5 py-1',
    lg: 'text-sm px-3.5 py-1.5 font-semibold',
  }[size];

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border ${styles.bg} ${styles.text} ${styles.border} ${sizeClasses} font-mono`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${styles.dot}`}></span>
      <span>{styles.label}</span>
      {score !== undefined && (
        <span className="font-bold opacity-90">({score}/100)</span>
      )}
    </span>
  );
};
