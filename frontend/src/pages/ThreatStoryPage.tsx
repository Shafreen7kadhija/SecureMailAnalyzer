import React, { useState, useEffect } from 'react';
import {
  Layers,
  Cpu,
  Shield,
  Download,
  AlertTriangle,
  RefreshCw,
  Clock,
  Search,
  Filter,
} from 'lucide-react';
import { ThreatStoryTimeline } from '../components/ThreatStoryTimeline';
import { QuarantineModal } from '../components/QuarantineModal';
import { SandboxImportModal } from '../components/SandboxImportModal';
import { fetchInvestigation, fetchInvestigations, getExportCsvUrl, getExportJsonUrl } from '../services/api';
import { Investigation } from '../types';

interface ThreatStoryPageProps {
  initialInvestigationId?: string;
  onNavigateToAnalyze: () => void;
}

export const ThreatStoryPage: React.FC<ThreatStoryPageProps> = ({
  initialInvestigationId,
  onNavigateToAnalyze,
}) => {
  const [investigationsList, setInvestigationsList] = useState<any[]>([]);
  const [selectedId, setSelectedId] = useState<string>(initialInvestigationId || '');
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Modals
  const [isQuarantineOpen, setIsQuarantineOpen] = useState<boolean>(false);
  const [isSandboxOpen, setIsSandboxOpen] = useState<boolean>(false);

  // Load investigations list
  useEffect(() => {
    fetchInvestigations('', '', 50, 0)
      .then((data) => {
        setInvestigationsList(data.investigations);
        if (!selectedId && data.investigations.length > 0) {
          setSelectedId(data.investigations[0].id);
        }
      })
      .catch((err) => console.error('Failed to list investigations', err));
  }, []);

  // When selectedId changes, fetch full investigation
  useEffect(() => {
    if (!selectedId) return;
    setLoading(true);
    setError(null);
    fetchInvestigation(selectedId)
      .then((data) => {
        setInvestigation(data);
      })
      .catch((err) => {
        setError(err.message || 'Failed to fetch investigation timeline');
      })
      .finally(() => setLoading(false));
  }, [selectedId]);

  return (
    <div className="space-y-6 animate-in fade-in duration-150">
      {/* Top Controls Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-2xl bg-[#0f172a] border border-slate-800 shadow-xl">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <Layers className="w-5 h-5 text-cyan-400" />
            <span>Attachment Threat Story Investigation</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Select an attachment investigation to inspect its correlated evidence timeline.
          </p>
        </div>

        {/* Investigation Switcher */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-400 whitespace-nowrap">Active Investigation:</span>
            <select
              value={selectedId}
              onChange={(e) => setSelectedId(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-white font-mono text-xs focus:outline-none focus:border-cyan-500 max-w-xs"
            >
              {investigationsList.map((inv) => (
                <option key={inv.id} value={inv.id}>
                  {inv.id} — {inv.filename} ({inv.severity})
                </option>
              ))}
            </select>
          </div>

          {investigation && (
            <div className="flex items-center gap-2">
              <a
                href={getExportJsonUrl(investigation.id)}
                download
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
                title="Download JSON Report"
              >
                <Download className="w-4 h-4" />
              </a>
            </div>
          )}
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="p-12 text-center text-slate-400 text-xs flex flex-col items-center justify-center gap-3">
          <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
          <span>Loading Chronological Threat Story...</span>
        </div>
      ) : investigation ? (
        <div className="space-y-6">
          {/* Quick Header Summary */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-wrap items-center justify-between gap-4 text-xs font-mono">
            <div className="flex items-center gap-3">
              <span className="text-slate-400">File:</span>
              <span className="text-white font-bold">{investigation.original_filename}</span>
              <span className="text-slate-500">•</span>
              <span className="text-slate-400">Format:</span>
              <span className="text-cyan-400">{investigation.detected_format}</span>
              <span className="text-slate-500">•</span>
              <span className="text-slate-400">Risk:</span>
              <span
                className={`font-bold ${
                  investigation.severity === 'CRITICAL'
                    ? 'text-rose-400'
                    : investigation.severity === 'HIGH'
                    ? 'text-orange-400'
                    : investigation.severity === 'MEDIUM'
                    ? 'text-amber-400'
                    : 'text-emerald-400'
                }`}
              >
                {investigation.severity} ({investigation.risk_score}/100)
              </span>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-slate-400">Quarantine Status:</span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                  investigation.quarantine_status === 'QUARANTINED'
                    ? 'bg-rose-950 text-rose-400 border border-rose-800'
                    : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                }`}
              >
                {investigation.quarantine_status}
              </span>
            </div>
          </div>

          {/* Chronological Timeline */}
          <ThreatStoryTimeline
            events={investigation.timeline}
            filename={investigation.original_filename}
            sha256={investigation.sha256}
            onOpenSandboxModal={() => setIsSandboxOpen(true)}
            onOpenQuarantineModal={() => setIsQuarantineOpen(true)}
          />

          {/* Modals */}
          <QuarantineModal
            investigation={investigation}
            isOpen={isQuarantineOpen}
            onClose={() => setIsQuarantineOpen(false)}
            onSuccess={(updated) => setInvestigation(updated)}
          />
          <SandboxImportModal
            investigation={investigation}
            isOpen={isSandboxOpen}
            onClose={() => setIsSandboxOpen(false)}
            onSuccess={(updated) => setInvestigation(updated)}
          />
        </div>
      ) : (
        <div className="p-12 text-center rounded-2xl bg-[#0f172a] border border-slate-800 text-slate-400 space-y-3">
          <p className="text-sm">No investigations available yet to display a Threat Story.</p>
          <button
            onClick={onNavigateToAnalyze}
            className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs transition"
          >
            Analyze First Attachment
          </button>
        </div>
      )}
    </div>
  );
};
