import React, { useState, useEffect } from 'react';
import {
  Clock,
  Search,
  Filter,
  RefreshCw,
  AlertTriangle,
  FileText,
  ArrowRight,
  Shield,
  Lock,
} from 'lucide-react';
import { RiskBadge } from '../components/RiskBadge';
import { fetchInvestigations } from '../services/api';
import { SeverityLevel } from '../types';

interface HistoryPageProps {
  onNavigateToStory: (investigationId: string) => void;
  onNavigateToAnalyze: (investigationId: string) => void;
}

export const HistoryPage: React.FC<HistoryPageProps> = ({
  onNavigateToStory,
  onNavigateToAnalyze,
}) => {
  const [investigations, setInvestigations] = useState<any[]>([]);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const loadInvestigations = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchInvestigations(searchTerm, severityFilter, 100, 0);
      setInvestigations(data.investigations);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch investigation history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadInvestigations();
  }, [severityFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadInvestigations();
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-150">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-2xl bg-[#0f172a] border border-slate-800 shadow-xl">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <Clock className="w-5 h-5 text-cyan-400" />
            <span>Investigation History Archive</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Persisted metadata records of past email attachment static inspections and threat stories.
          </p>
        </div>

        <button
          onClick={loadInvestigations}
          disabled={loading}
          className="p-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition self-start md:self-auto"
          title="Refresh History"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-4 rounded-xl bg-slate-900 border border-slate-800 text-xs">
        {/* Search */}
        <form onSubmit={handleSearchSubmit} className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search by filename, hash, or ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-950 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </form>

        {/* Severity Filter Tabs */}
        <div className="flex items-center gap-1.5 flex-wrap w-full sm:w-auto">
          <span className="text-slate-400 flex items-center gap-1 font-medium mr-1">
            <Filter className="w-3 h-3 text-cyan-400" /> Severity:
          </span>
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-2.5 py-1 rounded text-xs transition ${
                severityFilter === sev
                  ? 'bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Table */}
      <div className="rounded-2xl bg-[#0f172a] border border-slate-800 shadow-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/80 text-slate-400 uppercase tracking-wider font-mono text-[10px] border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Investigation ID</th>
                <th className="py-3 px-4">Filename</th>
                <th className="py-3 px-4">Format</th>
                <th className="py-3 px-4">SHA-256 Hash</th>
                <th className="py-3 px-4">Risk Level</th>
                <th className="py-3 px-4">Quarantine</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {investigations.length > 0 ? (
                investigations.map((inv) => (
                  <tr key={inv.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-4 font-mono font-medium text-cyan-400">{inv.id}</td>
                    <td className="py-3 px-4 font-medium text-white max-w-[180px] truncate">
                      {inv.filename}
                      {inv.is_synthetic_sample === 1 && (
                        <span className="ml-1.5 px-1 py-0.2 rounded text-[9px] bg-amber-500/20 text-amber-300 border border-amber-500/40 font-mono">
                          DEMO
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300">{inv.detected_format}</td>
                    <td className="py-3 px-4 font-mono text-slate-400 max-w-[140px] truncate" title={inv.sha256}>
                      {inv.sha256 ? inv.sha256.substring(0, 16) + '...' : 'N/A'}
                    </td>
                    <td className="py-3 px-4">
                      <RiskBadge severity={inv.severity as SeverityLevel} score={inv.risk_score} size="sm" />
                    </td>
                    <td className="py-3 px-4 font-mono">
                      {inv.quarantine_status === 'QUARANTINED' ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-rose-950 text-rose-400 border border-rose-800">
                          QUARANTINED
                        </span>
                      ) : (
                        <span className="text-slate-500">—</span>
                      )}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                      {new Date(inv.created_at).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 text-right space-x-2">
                      <button
                        onClick={() => onNavigateToAnalyze(inv.id)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-[11px] font-medium transition"
                      >
                        Details
                      </button>
                      <button
                        onClick={() => onNavigateToStory(inv.id)}
                        className="px-2.5 py-1 rounded bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 text-[11px] font-medium transition"
                      >
                        Threat Story
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="py-10 text-center text-slate-500">
                    No investigations match the current criteria.
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
