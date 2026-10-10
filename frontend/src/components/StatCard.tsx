import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  colorScheme?: 'cyan' | 'emerald' | 'amber' | 'rose' | 'slate';
  badge?: string;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  colorScheme = 'cyan',
  badge,
}) => {
  const schemes = {
    cyan: {
      border: 'border-cyan-900/40 hover:border-cyan-700/60',
      iconBg: 'bg-cyan-950/70 text-cyan-400 border border-cyan-800/60',
      glow: 'group-hover:shadow-cyan-950/20',
      text: 'text-cyan-400',
    },
    emerald: {
      border: 'border-emerald-900/40 hover:border-emerald-700/60',
      iconBg: 'bg-emerald-950/70 text-emerald-400 border border-emerald-800/60',
      glow: 'group-hover:shadow-emerald-950/20',
      text: 'text-emerald-400',
    },
    amber: {
      border: 'border-amber-900/40 hover:border-amber-700/60',
      iconBg: 'bg-amber-950/70 text-amber-400 border border-amber-800/60',
      glow: 'group-hover:shadow-amber-950/20',
      text: 'text-amber-400',
    },
    rose: {
      border: 'border-rose-900/40 hover:border-rose-700/60',
      iconBg: 'bg-rose-950/70 text-rose-400 border border-rose-800/60',
      glow: 'group-hover:shadow-rose-950/20',
      text: 'text-rose-400',
    },
    slate: {
      border: 'border-slate-800 hover:border-slate-700',
      iconBg: 'bg-slate-800 text-slate-300 border border-slate-700',
      glow: 'group-hover:shadow-slate-900/20',
      text: 'text-slate-300',
    },
  }[colorScheme];

  return (
    <div
      className={`group relative rounded-xl bg-[#0f172a] p-5 border ${schemes.border} transition-all duration-200 hover:-translate-y-0.5 shadow-lg ${schemes.glow}`}
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">{title}</p>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono tracking-tight text-white">{value}</span>
            {badge && (
              <span className="text-[10px] px-1.5 py-0.5 rounded font-mono font-semibold bg-slate-800 text-slate-300 border border-slate-700">
                {badge}
              </span>
            )}
          </div>
          {subtitle && <p className="mt-1 text-xs text-slate-400">{subtitle}</p>}
        </div>
        <div className={`p-2.5 rounded-lg ${schemes.iconBg}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  );
};
