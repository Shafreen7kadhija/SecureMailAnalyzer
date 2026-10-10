import React, { useEffect, useState } from 'react';
import {
  Shield,
  Upload,
  AlertTriangle,
  Lock,
  Layers,
  Clock,
  ArrowRight,
  TrendingUp,
  FileCheck,
  RefreshCw,
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  PieChart,
  Pie,
} from 'recharts';
import { StatCard } from '../components/StatCard';
import { RiskBadge } from '../components/RiskBadge';
import { fetchDashboardStats } from '../services/api';
import { DashboardStats } from '../types';

interface OverviewPageProps {
  onNavigate: (tab: string, investigationId?: string) => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({ onNavigate }) => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const loadStats = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchDashboardStats();
      setStats(data);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve live SOC metrics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadStats();
  }, []);

  const totalThreats = stats
    ? stats.severity_counts.HIGH + stats.severity_counts.CRITICAL
    : 0;

  return (
    <div className="space-y-8 animate-in fade-in duration-200">
      {/* Top Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-[#0e172a] to-cyan-950/50 border border-slate-800 p-6 sm:p-8 shadow-2xl">
        <div className="relative z-10 flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-cyan-950 text-cyan-300 border border-cyan-800/80">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
                SOC Live Operations Center
              </span>
              <span className="text-xs text-slate-400">• Windows Localhost 127.0.0.1</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              Email Attachment Security & Threat Story Platform
            </h1>
            <p className="mt-2 text-xs sm:text-sm text-slate-300 max-w-2xl leading-relaxed">
              Inspect suspicious attachments using bounded static signature inspection, explainable risk scoring, and our signature <strong className="text-cyan-300">Attachment Threat Story</strong> correlating observed telemetry with imported sandbox behavior.
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              onClick={loadStats}
              disabled={loading}
              className="p-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
              title="Refresh Live Statistics"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
            <button
              onClick={() => onNavigate('analyze')}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-sm shadow-lg shadow-cyan-500/20 transition hover:scale-[1.02]"
            >
              <Upload className="w-4 h-4" />
              <span>Analyze New Attachment</span>
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button onClick={loadStats} className="underline hover:text-white">Retry</button>
        </div>
      )}

      {/* Primary SOC Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Attachments Analyzed"
          value={stats ? stats.total_analyzed : '...'}
          subtitle="Persistent database records"
          icon={FileCheck}
          colorScheme="cyan"
          badge="LIVE"
        />
        <StatCard
          title="Elevated Threats (High/Crit)"
          value={stats ? totalThreats : '...'}
          subtitle={`${stats ? stats.severity_counts.CRITICAL : 0} Critical, ${stats ? stats.severity_counts.HIGH : 0} High`}
          icon={AlertTriangle}
          colorScheme="rose"
        />
        <StatCard
          title="Simulated Quarantine"
          value={stats ? stats.quarantined_count : '...'}
          subtitle="Controlled isolation state"
          icon={Lock}
          colorScheme="amber"
        />
        <StatCard
          title="Sandbox Correlated"
          value={stats ? stats.sandbox_correlated_count : '...'}
          subtitle="Dynamic Threat Stories"
          icon={Layers}
          colorScheme="emerald"
        />
      </div>

      {/* Charts & Severity Distribution Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Breakdown Card */}
        <div className="lg:col-span-2 rounded-2xl bg-[#0f172a] border border-slate-800 p-6 shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider">Risk Score Distribution</h2>
              <p className="text-xs text-slate-400">Investigations segmented by deterministic severity thresholds</p>
            </div>
            <div className="flex items-center gap-3 text-[11px] font-mono">
              <span className="flex items-center gap-1 text-emerald-400"><span className="w-2 h-2 rounded-full bg-emerald-400"></span>Low</span>
              <span className="flex items-center gap-1 text-amber-400"><span className="w-2 h-2 rounded-full bg-amber-400"></span>Med</span>
              <span className="flex items-center gap-1 text-orange-400"><span className="w-2 h-2 rounded-full bg-orange-400"></span>High</span>
              <span className="flex items-center gap-1 text-rose-400"><span className="w-2 h-2 rounded-full bg-rose-400"></span>Crit</span>
            </div>
          </div>

          <div className="h-64 w-full">
            {stats && stats.risk_distribution && (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.risk_distribution} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                    labelStyle={{ color: '#94a3b8' }}
                  />
                  <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                    {stats.risk_distribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Quick Launch & Differentiator Highlight */}
        <div className="rounded-2xl bg-gradient-to-b from-[#131b31] to-[#0f172a] border border-cyan-900/40 p-6 flex flex-col justify-between shadow-xl">
          <div>
            <div className="flex items-center gap-2 mb-3">
              <span className="p-2 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-800">
                <Layers className="w-5 h-5" />
              </span>
              <h2 className="text-base font-bold text-white tracking-tight">Attachment Threat Story</h2>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed mb-4">
              Unlike black-box scanners, SecureMailAnalyzer creates an explainable chronological story detailing file metadata, magic signatures, static heuristics, sandbox behavioral telemetry, and simulated containment.
            </p>
            <div className="p-3 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2 text-xs">
              <div className="font-semibold text-cyan-300">Supported Safe Analysis:</div>
              <ul className="space-y-1 text-slate-400 text-[11px]">
                <li>• Bounded PDF object & JavaScript analysis</li>
                <li>• In-memory Office macro (vbaProject.bin) detection</li>
                <li>• Double-extension and RTL override detection</li>
                <li>• Disguised PE binaries & magic byte mismatches</li>
                <li>• Non-destructive Sandbox JSON import</li>
              </ul>
            </div>
          </div>

          <div className="pt-4 border-t border-slate-800">
            <button
              onClick={() => onNavigate('threat-story')}
              className="w-full py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-800/60 font-semibold text-xs flex items-center justify-center gap-2 transition"
            >
              <span>Explore Threat Story View</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Recent Investigations Table */}
      <div className="rounded-2xl bg-[#0f172a] border border-slate-800 shadow-xl overflow-hidden">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">Recent Investigations</h2>
          </div>
          <button
            onClick={() => onNavigate('history')}
            className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium transition"
          >
            <span>View Full History</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/80 text-slate-400 uppercase tracking-wider font-mono text-[10px] border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Investigation ID</th>
                <th className="py-3 px-4">Filename</th>
                <th className="py-3 px-4">SHA-256 Hash</th>
                <th className="py-3 px-4">Risk Level</th>
                <th className="py-3 px-4">Quarantine</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {stats && stats.recent_investigations.length > 0 ? (
                stats.recent_investigations.map((inv) => (
                  <tr key={inv.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-4 font-mono font-medium text-cyan-400">{inv.id}</td>
                    <td className="py-3 px-4 font-medium text-white max-w-[180px] truncate">
                      {inv.filename}
                      {inv.is_synthetic_sample && (
                        <span className="ml-1.5 px-1 py-0.2 rounded text-[9px] bg-amber-500/20 text-amber-300 border border-amber-500/40 font-mono">
                          DEMO
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400 max-w-[160px] truncate" title={inv.sha256}>
                      {inv.sha256.substring(0, 16)}...
                    </td>
                    <td className="py-3 px-4">
                      <RiskBadge severity={inv.severity} score={inv.risk_score} size="sm" />
                    </td>
                    <td className="py-3 px-4 font-mono">
                      {inv.quarantine_status === 'QUARANTINED' ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-rose-950 text-rose-400 border border-rose-800">
                          QUARANTINED
                        </span>
                      ) : (
                        <span className="text-slate-500 text-[11px]">—</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => onNavigate('threat-story', inv.id)}
                        className="px-2.5 py-1 rounded bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 text-[11px] font-medium transition"
                      >
                        Inspect Story
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    No investigations logged yet. Click "Analyze New Attachment" to begin.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
